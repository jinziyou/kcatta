//! Installed packages from the rpm database.
//!
//! Modern rpm (RHEL 8+, Fedora, Rocky, Alma) stores headers in SQLite
//! (`var/lib/rpm/rpmdb.sqlite`). openSUSE and some rpm 4.16+ builds use the
//! ndb backend (`var/lib/rpm/Packages.db`). Older releases (RHEL 7 / CentOS 7)
//! use a Berkeley DB hash file at `var/lib/rpm/Packages`; ndb/BDB paths locate
//! header blobs by structure without linking `libdb`.

use std::collections::HashSet;
use std::path::Path;

use agent_contract::{Asset, Package};
use rusqlite::{Connection, OpenFlags};

use crate::root::join_root;
use crate::sbom::read_distro;
use crate::ScanContext;

const RPMDB_SQLITE: &str = "var/lib/rpm/rpmdb.sqlite";
const RPMDB_NDB: &str = "var/lib/rpm/Packages.db";
const RPMDB_BDB: &str = "var/lib/rpm/Packages";

/// Upper bound on an rpm database file read into memory (bounds OOM from a huge
/// or crafted DB when scanning an untrusted mounted image / container rootfs).
const RPMDB_MAX_BYTES: u64 = 256 * 1024 * 1024;

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
    let sqlite_path = join_root(ctx, RPMDB_SQLITE);
    if sqlite_path.is_file() {
        let pkgs = rpm_packages_sqlite(&sqlite_path);
        if !pkgs.is_empty() {
            return pkgs;
        }
    }
    let ndb_path = join_root(ctx, RPMDB_NDB);
    if ndb_path.is_file() {
        let pkgs = rpm_packages_blob_scan(&ndb_path);
        if !pkgs.is_empty() {
            return pkgs;
        }
    }
    let bdb_path = join_root(ctx, RPMDB_BDB);
    if bdb_path.is_file() {
        return rpm_packages_blob_scan(&bdb_path);
    }
    Vec::new()
}

fn rpm_packages_sqlite(path: &Path) -> Vec<RpmPackage> {
    let Ok(conn) = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY) else {
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

/// Read a file into memory, capped at `cap` bytes (warns and truncates if larger).
fn read_capped(path: &Path, cap: u64) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    f.by_ref().take(cap).read_to_end(&mut buf).ok()?;
    let mut probe = [0u8; 1];
    if matches!(f.read(&mut probe), Ok(n) if n > 0) {
        eprintln!(
            "agent-host: rpm database {} exceeds {cap} bytes; scanning first {cap} only",
            path.display()
        );
    }
    Some(buf)
}

/// Byte span (`8 + nindex*16 + hsize`) of a valid header at the start of `blob`.
fn header_span(blob: &[u8]) -> Option<usize> {
    let nindex = be32(blob, 0)? as usize;
    let hsize = be32(blob, 4)? as usize;
    if nindex == 0 || nindex > 512 || hsize == 0 || hsize > 2 * 1024 * 1024 {
        return None;
    }
    let data_start = 8usize.checked_add(nindex.checked_mul(16)?)?;
    data_start.checked_add(hsize)
}

/// Scan ndb/BDB rpm database files for embedded header blobs.
fn rpm_packages_blob_scan(path: &Path) -> Vec<RpmPackage> {
    let Some(data) = read_capped(path, RPMDB_MAX_BYTES) else {
        return Vec::new();
    };
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    // Headers may start at any byte offset inside BDB pages. On a successful parse
    // we advance past the whole header rather than re-scanning its interior byte
    // by byte (avoids quadratic work on large databases).
    let mut offset = 0usize;
    let end = data.len().saturating_sub(32);
    while offset < end {
        if let Some(pkg) = parse_header(&data[offset..]) {
            if looks_like_rpm_name(&pkg.name) {
                if seen.insert((pkg.name.clone(), pkg.evr.clone())) {
                    out.push(pkg);
                }
                if let Some(span) = header_span(&data[offset..]) {
                    offset += span.max(1);
                    continue;
                }
            }
        }
        offset += 1;
    }
    out
}

fn looks_like_rpm_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '+' | '.' | ':'))
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
    if nindex == 0 || nindex > 512 || hsize == 0 || hsize > 2 * 1024 * 1024 {
        return None;
    }
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
        parent_asset_id: None,
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
    fn collect_reads_bdb_packages_file() {
        let temp = tempfile::tempdir().unwrap();
        let bdb_path = temp.path().join(RPMDB_BDB);
        std::fs::create_dir_all(bdb_path.parent().unwrap()).unwrap();
        std::fs::write(&bdb_path, b"padding-before").unwrap();
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&bdb_path)
            .unwrap();
        use std::io::Write;
        file.write_all(&nginx_blob()).unwrap();
        file.write_all(b"padding-after").unwrap();

        let os_release = temp.path().join("etc/os-release");
        std::fs::create_dir_all(os_release.parent().unwrap()).unwrap();
        std::fs::write(&os_release, "ID=centos\nVERSION_ID=\"7\"\n").unwrap();

        let ctx = ScanContext::at(temp.path());
        let assets = collect(&ctx);
        assert_eq!(assets.len(), 1);
        match &assets[0] {
            Asset::Package(p) => {
                assert_eq!(p.name, "nginx");
                assert_eq!(p.version, "1:1.20.4-1.el9");
                assert_eq!(p.source.as_deref(), Some("rpm"));
                assert_eq!(p.ecosystem, None);
            }
            other => panic!("expected package, got {other:?}"),
        }
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

    #[test]
    fn collect_reads_ndb_packages_db() {
        let temp = tempfile::tempdir().unwrap();
        let ndb_path = temp.path().join(RPMDB_NDB);
        std::fs::create_dir_all(ndb_path.parent().unwrap()).unwrap();
        std::fs::write(&ndb_path, b"ndb-page-padding").unwrap();
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&ndb_path)
            .unwrap();
        use std::io::Write;
        file.write_all(&nginx_blob()).unwrap();

        let os_release = temp.path().join("etc/os-release");
        std::fs::create_dir_all(os_release.parent().unwrap()).unwrap();
        std::fs::write(
            &os_release,
            "ID=opensuse-tumbleweed\nVERSION_ID=\"20240501\"\n",
        )
        .unwrap();

        let ctx = ScanContext::at(temp.path());
        let assets = collect(&ctx);
        assert_eq!(assets.len(), 1);
        match &assets[0] {
            Asset::Package(p) => {
                assert_eq!(p.name, "nginx");
                assert_eq!(p.version, "1:1.20.4-1.el9");
                assert_eq!(p.source.as_deref(), Some("rpm"));
            }
            other => panic!("expected package, got {other:?}"),
        }
    }

    #[test]
    fn blob_scan_dedupes_identical_headers() {
        let temp = tempfile::tempdir().unwrap();
        let bdb_path = temp.path().join("Packages");
        let blob = nginx_blob();
        let mut data = Vec::new();
        data.extend_from_slice(&blob);
        data.extend_from_slice(&blob);
        std::fs::write(&bdb_path, data).unwrap();

        let pkgs = rpm_packages_blob_scan(&bdb_path);
        assert_eq!(pkgs.len(), 1);
    }
}
