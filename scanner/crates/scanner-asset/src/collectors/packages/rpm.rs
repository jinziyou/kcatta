//! Installed packages from the rpm database (`var/lib/rpm/rpmdb.sqlite`).
//!
//! Modern rpm (RHEL 8+, Fedora, Rocky, Alma, openSUSE) stores headers as blobs
//! in a SQLite `Packages` table. We read that table read-only and parse each
//! rpm *header* blob in pure Rust to pull NAME / EPOCH / VERSION / RELEASE.
//! Older Berkeley-DB / ndb backends are not supported.
//!
//! Header blob layout (all integers big-endian), as produced by `headerExport`:
//! `[nindex u32][hstore_size u32][nindex * 16-byte index entries][data store]`.
//! Each index entry is `[tag u32][type u32][offset u32][count u32]`; string
//! values are NUL-terminated at `data[offset]`, INT32 values are 4 BE bytes.

use rusqlite::{Connection, OpenFlags};
use scanner_contract::{Asset, Package};

use crate::root::join_root;
use crate::sbom::read_distro;
use scanner_runtime::ScanContext;

const RPMDB_SQLITE: &str = "var/lib/rpm/rpmdb.sqlite";

const TAG_NAME: u32 = 1000;
const TAG_VERSION: u32 = 1001;
const TAG_RELEASE: u32 = 1002;
const TAG_EPOCH: u32 = 1003;
const TYPE_INT32: u32 = 4;
const TYPE_STRING: u32 = 6;

/// One installed rpm package, version rendered as an EVR (`epoch:version-release`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpmPackage {
    pub name: String,
    pub evr: String,
}

/// Installed rpm packages as contract [`Asset`]s.
pub fn collect(ctx: &ScanContext) -> Vec<Asset> {
    let ecosystem = read_distro(ctx).osv_ecosystem();
    rpm_packages(ctx)
        .into_iter()
        .map(|pkg| into_asset(pkg, ecosystem.clone()))
        .collect()
}

fn rpm_packages(ctx: &ScanContext) -> Vec<RpmPackage> {
    let path = join_root(ctx, RPMDB_SQLITE);
    if !path.exists() {
        return Vec::new();
    }
    let Ok(conn) = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY) else {
        return Vec::new();
    };
    let Ok(mut stmt) = conn.prepare("SELECT blob FROM Packages") else {
        return Vec::new();
    };
    let Ok(rows) = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0)) else {
        return Vec::new();
    };
    rows.flatten()
        .filter_map(|blob| parse_header(&blob))
        .collect()
}

fn be32(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_string(data: &[u8], offset: usize) -> Option<String> {
    let bytes = data.get(offset..)?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

/// Parse NAME / EPOCH / VERSION / RELEASE out of an rpm header blob.
pub fn parse_header(blob: &[u8]) -> Option<RpmPackage> {
    let nindex = be32(blob, 0)? as usize;
    let hsize = be32(blob, 4)? as usize;
    let index_start = 8usize;
    let data_start = index_start.checked_add(nindex.checked_mul(16)?)?;
    let data_end = data_start.checked_add(hsize)?;
    if blob.len() < data_end {
        return None;
    }
    let data = &blob[data_start..data_end];

    let mut name = None;
    let mut version = None;
    let mut release = None;
    let mut epoch = None;
    for i in 0..nindex {
        let entry = index_start + i * 16;
        let tag = be32(blob, entry)?;
        let typ = be32(blob, entry + 4)?;
        let offset = be32(blob, entry + 8)? as usize;
        match (tag, typ) {
            (TAG_NAME, TYPE_STRING) => name = read_string(data, offset),
            (TAG_VERSION, TYPE_STRING) => version = read_string(data, offset),
            (TAG_RELEASE, TYPE_STRING) => release = read_string(data, offset),
            (TAG_EPOCH, TYPE_INT32) => epoch = be32(data, offset),
            _ => {}
        }
    }
    let name = name?;
    let version = version?;
    let release = release?;
    if name.is_empty() || version.is_empty() {
        return None;
    }
    let evr = format!("{}:{}-{}", epoch.unwrap_or(0), version, release);
    Some(RpmPackage { name, evr })
}

fn into_asset(pkg: RpmPackage, ecosystem: Option<String>) -> Asset {
    Asset::Package(Package {
        asset_id: format!("rpm-{}", pkg.name),
        name: pkg.name,
        version: pkg.evr,
        source: Some("rpm".to_string()),
        install_path: None,
        ecosystem,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal header blob from `(tag, type, payload)` entries.
    fn build_blob(entries: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
        let mut data = Vec::new();
        let mut index = Vec::new();
        for (tag, typ, payload) in entries {
            let offset = data.len() as u32;
            index.extend_from_slice(&tag.to_be_bytes());
            index.extend_from_slice(&typ.to_be_bytes());
            index.extend_from_slice(&offset.to_be_bytes());
            index.extend_from_slice(&1u32.to_be_bytes()); // count
            data.extend_from_slice(payload);
        }
        let mut blob = Vec::new();
        blob.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        blob.extend_from_slice(&(data.len() as u32).to_be_bytes());
        blob.extend_from_slice(&index);
        blob.extend_from_slice(&data);
        blob
    }

    fn nginx_blob() -> Vec<u8> {
        build_blob(&[
            (TAG_NAME, TYPE_STRING, b"nginx\0".to_vec()),
            (TAG_EPOCH, TYPE_INT32, 1u32.to_be_bytes().to_vec()),
            (TAG_VERSION, TYPE_STRING, b"1.20.4\0".to_vec()),
            (TAG_RELEASE, TYPE_STRING, b"1.el9\0".to_vec()),
        ])
    }

    #[test]
    fn parse_header_extracts_evr() {
        let pkg = parse_header(&nginx_blob()).unwrap();
        assert_eq!(pkg.name, "nginx");
        assert_eq!(pkg.evr, "1:1.20.4-1.el9");
    }

    #[test]
    fn parse_header_defaults_epoch_zero() {
        let blob = build_blob(&[
            (TAG_NAME, TYPE_STRING, b"zlib\0".to_vec()),
            (TAG_VERSION, TYPE_STRING, b"1.2.13\0".to_vec()),
            (TAG_RELEASE, TYPE_STRING, b"2.el9\0".to_vec()),
        ]);
        let pkg = parse_header(&blob).unwrap();
        assert_eq!(pkg.evr, "0:1.2.13-2.el9");
    }

    #[test]
    fn parse_header_rejects_truncated_blob() {
        let mut blob = nginx_blob();
        blob.truncate(blob.len() - 3);
        assert!(parse_header(&blob).is_none());
    }

    #[test]
    fn collect_reads_sqlite_rpmdb() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(RPMDB_SQLITE);
        std::fs::create_dir_all(db_path.parent().unwrap()).unwrap();
        let os_release = temp.path().join("etc/os-release");
        std::fs::create_dir_all(os_release.parent().unwrap()).unwrap();
        std::fs::write(&os_release, "ID=rocky\nVERSION_ID=\"9.3\"\n").unwrap();

        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute(
                "CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB NOT NULL)",
                [],
            )
            .unwrap();
            conn.execute("INSERT INTO Packages (blob) VALUES (?1)", [nginx_blob()])
                .unwrap();
        }

        let ctx = ScanContext::at(temp.path());
        let assets = collect(&ctx);
        assert_eq!(assets.len(), 1);
        match &assets[0] {
            Asset::Package(p) => {
                assert_eq!(p.name, "nginx");
                assert_eq!(p.version, "1:1.20.4-1.el9");
                assert_eq!(p.source.as_deref(), Some("rpm"));
                assert_eq!(p.ecosystem.as_deref(), Some("Rocky Linux:9"));
            }
            other => panic!("expected package, got {other:?}"),
        }
    }
}
