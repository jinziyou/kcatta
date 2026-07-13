//! Secure local audit-log file handling.

use std::io;
use std::path::Path;

#[cfg_attr(
    any(not(unix), target_os = "redox", target_os = "solaris"),
    allow(dead_code)
)]
pub(super) enum AppendOutcome {
    Written,
    Reset,
    RecordTooLarge,
}

#[cfg(all(unix, not(any(target_os = "redox", target_os = "solaris"))))]
mod platform {
    use std::fs::{self, DirBuilder, File, Metadata, OpenOptions};
    use std::io::{self, Write};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::{Component, Path, PathBuf};

    use nix::fcntl::{Flock, FlockArg};
    use nix::unistd::Uid;

    struct PreparedParent {
        path: PathBuf,
        handle: File,
        migrate: bool,
    }

    pub(super) fn prepare(path: &Path) -> io::Result<()> {
        drop(open_secure(path)?);
        Ok(())
    }

    pub(super) fn append(
        path: &Path,
        bytes: &[u8],
        max_bytes: u64,
    ) -> io::Result<super::AppendOutcome> {
        let file = open_secure(path)?;
        let mut file = Flock::lock(file, FlockArg::LockExclusive)
            .map_err(|(_file, errno)| io::Error::from_raw_os_error(errno as i32))?;
        validate_private_file(&file.metadata()?, false)?;

        let current = file.metadata()?.len();
        let incoming = u64::try_from(bytes.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "audit record length overflow")
        })?;
        if incoming > max_bytes {
            return Ok(super::AppendOutcome::RecordTooLarge);
        }
        let reset = current
            .checked_add(incoming)
            .is_none_or(|total| total > max_bytes);
        if reset {
            // Reset in place while holding the inode lock. A rename-based
            // rotation adds another path/link boundary and doubles the disk
            // budget; this keeps the one configured file strictly bounded.
            file.set_len(0)?;
        }
        file.write_all(bytes)?;
        file.sync_data()?;
        Ok(if reset {
            super::AppendOutcome::Reset
        } else {
            super::AppendOutcome::Written
        })
    }

    fn open_secure(path: &Path) -> io::Result<File> {
        let path = clean_absolute(path)?;
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "audit log has no parent directory",
            )
        })?;
        let prepared_parent = prepare_parent(parent)?;
        let (file, migrate_file) = open_or_create_file(&path)?;

        // A broad legacy directory is only safe to harden when it is dedicated
        // to this audit file. Validate its complete contents before changing a
        // single permission bit; this avoids chmod'ing a shared directory such
        // as /var/log due to a bad configuration value.
        if prepared_parent.migrate {
            validate_legacy_parent_contents(&prepared_parent.path, &path)?;
        }

        if migrate_file {
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        if prepared_parent.migrate {
            prepared_parent
                .handle
                .set_permissions(fs::Permissions::from_mode(0o700))?;
        }

        validate_private_dir(&prepared_parent.handle.metadata()?, false)?;
        validate_path_matches_handle(&prepared_parent.path, &prepared_parent.handle, true, false)?;
        validate_private_file(&file.metadata()?, false)?;
        validate_path_matches_handle(&path, &file, false, false)?;
        validate_trusted_ancestors(&prepared_parent.path)?;
        Ok(file)
    }

    fn clean_absolute(path: &Path) -> io::Result<PathBuf> {
        if path.as_os_str().is_empty()
            || path
                .components()
                .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "audit log path must be non-empty and contain no '..' components",
            ));
        }
        let absolute = std::path::absolute(path)?;
        if absolute.file_name().is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "audit log path must name a file",
            ));
        }
        Ok(absolute)
    }

    fn prepare_parent(path: &Path) -> io::Result<PreparedParent> {
        match fs::symlink_metadata(path) {
            Ok(_) => {
                validate_trusted_ancestors(path)?;
                let handle = open_dir_nofollow(path)?;
                let migrate = validate_private_dir(&handle.metadata()?, true)?;
                validate_path_matches_handle(path, &handle, true, migrate)?;
                Ok(PreparedParent {
                    path: path.to_path_buf(),
                    handle,
                    migrate,
                })
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                create_private_dir_all(path)?;
                validate_trusted_ancestors(path)?;
                let handle = open_dir_nofollow(path)?;
                validate_private_dir(&handle.metadata()?, false)?;
                validate_path_matches_handle(path, &handle, true, false)?;
                Ok(PreparedParent {
                    path: path.to_path_buf(),
                    handle,
                    migrate: false,
                })
            }
            Err(error) => Err(error),
        }
    }

    fn create_private_dir_all(path: &Path) -> io::Result<()> {
        let mut missing = Vec::new();
        let mut cursor = path;
        loop {
            match fs::symlink_metadata(cursor) {
                Ok(_) => {
                    validate_trusted_parent_chain(cursor)?;
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    missing.push(cursor.to_path_buf());
                    cursor = cursor.parent().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "audit log path has no existing ancestor",
                        )
                    })?;
                }
                Err(error) => return Err(error),
            }
        }

        for component in missing.into_iter().rev() {
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            let created = match builder.create(&component) {
                Ok(()) => true,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
                Err(error) => return Err(error),
            };
            let handle = open_dir_nofollow(&component)?;
            if created {
                // Apply the exact mode to the just-created inode through its
                // descriptor. Never chmod an unvalidated pre-existing path.
                handle.set_permissions(fs::Permissions::from_mode(0o700))?;
            }
            validate_private_dir(&handle.metadata()?, false)?;
            validate_path_matches_handle(&component, &handle, true, false)?;
        }
        Ok(())
    }

    fn open_or_create_file(path: &Path) -> io::Result<(File, bool)> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                validate_private_file(&metadata, true)?;
                let file = open_file_nofollow(path, false)?;
                let migrate = validate_private_file(&file.metadata()?, true)?;
                validate_path_matches_handle(path, &file, false, migrate)?;
                Ok((file, migrate))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match open_file_nofollow(path, true) {
                    Ok(file) => {
                        file.set_permissions(fs::Permissions::from_mode(0o600))?;
                        validate_private_file(&file.metadata()?, false)?;
                        validate_path_matches_handle(path, &file, false, false)?;
                        Ok((file, false))
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        // A concurrent creator won. It is accepted only if it
                        // independently satisfies the existing-file policy.
                        open_or_create_file(path)
                    }
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        }
    }

    fn open_dir_nofollow(path: &Path) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY);
        options.open(path)
    }

    fn open_file_nofollow(path: &Path, create_new: bool) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options
            .append(true)
            .create_new(create_new)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW);
        options.open(path)
    }

    fn validate_private_dir(metadata: &Metadata, legacy_allowed: bool) -> io::Result<bool> {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(permission_error("audit parent is not a real directory"));
        }
        validate_owner(metadata, "audit parent")?;
        let mode = metadata.mode() & 0o7777;
        if mode == 0o700 {
            return Ok(false);
        }
        if legacy_allowed && mode & 0o7022 == 0 {
            return Ok(true);
        }
        Err(permission_error(format!(
            "audit parent mode {mode:04o} is not 0700"
        )))
    }

    fn validate_private_file(metadata: &Metadata, legacy_allowed: bool) -> io::Result<bool> {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(permission_error("audit log is not a regular file"));
        }
        validate_owner(metadata, "audit log")?;
        if metadata.nlink() != 1 {
            return Err(permission_error(format!(
                "audit log has unexpected hard-link count {}",
                metadata.nlink()
            )));
        }
        let mode = metadata.mode() & 0o7777;
        if mode == 0o600 {
            return Ok(false);
        }
        if legacy_allowed && mode & 0o7022 == 0 {
            return Ok(true);
        }
        Err(permission_error(format!(
            "audit log mode {mode:04o} is not 0600"
        )))
    }

    fn validate_owner(metadata: &Metadata, label: &str) -> io::Result<()> {
        validate_owner_for(metadata, Uid::effective().as_raw(), label)
    }

    fn validate_owner_for(metadata: &Metadata, expected_uid: u32, label: &str) -> io::Result<()> {
        if metadata.uid() != expected_uid {
            return Err(permission_error(format!(
                "{label} owner uid {} does not match effective uid {expected_uid}",
                metadata.uid()
            )));
        }
        Ok(())
    }

    fn validate_legacy_parent_contents(parent: &Path, audit_path: &Path) -> io::Result<()> {
        let expected = audit_path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "audit log has no file name")
        })?;
        for entry in fs::read_dir(parent)? {
            let entry = entry?;
            if entry.file_name() != expected {
                return Err(permission_error(format!(
                    "legacy audit parent contains unexpected entry {:?}",
                    entry.file_name()
                )));
            }
            let metadata = fs::symlink_metadata(entry.path())?;
            validate_private_file(&metadata, true)?;
        }
        Ok(())
    }

    fn validate_path_matches_handle(
        path: &Path,
        handle: &File,
        directory: bool,
        legacy_allowed: bool,
    ) -> io::Result<()> {
        let path_metadata = fs::symlink_metadata(path)?;
        let handle_metadata = handle.metadata()?;
        if path_metadata.dev() != handle_metadata.dev()
            || path_metadata.ino() != handle_metadata.ino()
        {
            return Err(permission_error(format!(
                "audit {} changed during validation: {}",
                if directory { "parent" } else { "log" },
                path.display()
            )));
        }
        if directory {
            validate_private_dir(&path_metadata, legacy_allowed)?;
        } else {
            validate_private_file(&path_metadata, legacy_allowed)?;
        }
        Ok(())
    }

    fn validate_trusted_ancestors(path: &Path) -> io::Result<()> {
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "audit parent has no ancestor")
        })?;
        validate_trusted_parent_chain(parent)
    }

    fn validate_trusted_parent_chain(path: &Path) -> io::Result<()> {
        let current_uid = Uid::effective().as_raw();
        for ancestor in path.ancestors() {
            let metadata = fs::symlink_metadata(ancestor)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(permission_error(format!(
                    "audit ancestor is not a real directory: {}",
                    ancestor.display()
                )));
            }
            if metadata.uid() != current_uid && metadata.uid() != 0 {
                return Err(permission_error(format!(
                    "audit ancestor {} is owned by untrusted uid {}",
                    ancestor.display(),
                    metadata.uid()
                )));
            }
            let mode = metadata.mode();
            if mode & 0o022 != 0 && mode & 0o1000 == 0 {
                return Err(permission_error(format!(
                    "audit ancestor {} is writable by group/world without the sticky bit",
                    ancestor.display()
                )));
            }
        }
        Ok(())
    }

    fn permission_error(message: impl Into<String>) -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, message.into())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::Read;
        use std::os::unix::fs::{symlink, PermissionsExt};

        fn make_parent(root: &Path, mode: u32) -> PathBuf {
            let parent = root.join("kcatta");
            fs::create_dir(&parent).unwrap();
            fs::set_permissions(&parent, fs::Permissions::from_mode(mode)).unwrap();
            parent
        }

        #[test]
        fn creates_private_parent_and_file_and_appends() {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("nested/kcatta/audit.ndjson");
            append(&path, b"one\n", 1024).unwrap();
            append(&path, b"two\n", 1024).unwrap();

            for parent in [
                root.path().join("nested"),
                root.path().join("nested/kcatta"),
            ] {
                let metadata = fs::symlink_metadata(parent).unwrap();
                assert_eq!(metadata.mode() & 0o7777, 0o700);
                assert_eq!(metadata.uid(), Uid::effective().as_raw());
            }
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert_eq!(metadata.mode() & 0o7777, 0o600);
            assert_eq!(metadata.uid(), Uid::effective().as_raw());
            assert_eq!(metadata.nlink(), 1);
            assert_eq!(fs::read(&path).unwrap(), b"one\ntwo\n");
        }

        #[test]
        fn migrates_safe_legacy_layout_after_complete_validation() {
            let root = tempfile::tempdir().unwrap();
            let parent = make_parent(root.path(), 0o755);
            let path = parent.join("audit.ndjson");
            fs::write(&path, b"old\n").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

            prepare(&path).unwrap();
            assert_eq!(
                fs::symlink_metadata(&parent).unwrap().mode() & 0o7777,
                0o700
            );
            assert_eq!(fs::symlink_metadata(&path).unwrap().mode() & 0o7777, 0o600);
            append(&path, b"new\n", 1024).unwrap();
            assert_eq!(fs::read(&path).unwrap(), b"old\nnew\n");
        }

        #[test]
        fn rejects_unsafe_legacy_file_without_partially_chmodding_parent() {
            let root = tempfile::tempdir().unwrap();
            let parent = make_parent(root.path(), 0o755);
            let path = parent.join("audit.ndjson");
            fs::write(&path, b"old\n").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();

            assert!(prepare(&path).is_err());
            assert_eq!(
                fs::symlink_metadata(&parent).unwrap().mode() & 0o7777,
                0o755
            );
            assert_eq!(fs::symlink_metadata(&path).unwrap().mode() & 0o7777, 0o666);
        }

        #[test]
        fn rejects_legacy_parent_with_unexpected_entries_without_chmod() {
            let root = tempfile::tempdir().unwrap();
            let parent = make_parent(root.path(), 0o755);
            let path = parent.join("audit.ndjson");
            fs::write(&path, b"old\n").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            fs::write(parent.join("other.log"), b"other").unwrap();

            assert!(prepare(&path).is_err());
            assert_eq!(
                fs::symlink_metadata(&parent).unwrap().mode() & 0o7777,
                0o755
            );
            assert_eq!(fs::symlink_metadata(&path).unwrap().mode() & 0o7777, 0o644);
        }

        #[test]
        fn rejects_symlink_file_without_touching_target() {
            let root = tempfile::tempdir().unwrap();
            let parent = make_parent(root.path(), 0o700);
            let victim = root.path().join("victim");
            fs::write(&victim, b"keep").unwrap();
            fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).unwrap();
            let path = parent.join("audit.ndjson");
            symlink(&victim, &path).unwrap();

            assert!(append(&path, b"bad\n", 1024).is_err());
            assert_eq!(fs::read(victim).unwrap(), b"keep");
        }

        #[test]
        fn rejects_symlink_parent_and_does_not_create_through_it() {
            let root = tempfile::tempdir().unwrap();
            let victim = make_parent(root.path(), 0o700);
            let link = root.path().join("redirect");
            symlink(&victim, &link).unwrap();
            let path = link.join("audit.ndjson");

            assert!(prepare(&path).is_err());
            assert!(!victim.join("audit.ndjson").exists());
        }

        #[test]
        fn rejects_hardlinked_log() {
            let root = tempfile::tempdir().unwrap();
            let parent = make_parent(root.path(), 0o700);
            let path = parent.join("audit.ndjson");
            fs::write(&path, b"keep").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            fs::hard_link(&path, root.path().join("second-link")).unwrap();

            assert!(append(&path, b"bad\n", 1024).is_err());
            assert_eq!(fs::read(path).unwrap(), b"keep");
        }

        #[test]
        fn rejects_world_writable_untrusted_ancestor() {
            let root = tempfile::tempdir().unwrap();
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777)).unwrap();
            let parent = root.path().join("kcatta");
            fs::create_dir(&parent).unwrap();
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();

            assert!(prepare(&parent.join("audit.ndjson")).is_err());
            assert!(!parent.join("audit.ndjson").exists());
        }

        #[test]
        fn owner_validator_rejects_uid_mismatch() {
            let root = tempfile::tempdir().unwrap();
            let metadata = fs::symlink_metadata(root.path()).unwrap();
            let actual = metadata.uid();
            let other = if actual == u32::MAX {
                actual - 1
            } else {
                actual + 1
            };
            assert!(validate_owner_for(&metadata, other, "test").is_err());
        }

        #[test]
        fn byte_limit_is_enforced_without_partial_record() {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("kcatta/audit.ndjson");
            append(&path, b"1234", 6).unwrap();
            assert!(matches!(
                append(&path, b"567", 6).unwrap(),
                super::super::AppendOutcome::Reset
            ));
            let mut contents = Vec::new();
            File::open(path)
                .unwrap()
                .read_to_end(&mut contents)
                .unwrap();
            assert_eq!(contents, b"567");
        }

        #[test]
        fn oversized_record_is_dropped_without_growing_or_resetting_log() {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("kcatta/audit.ndjson");
            append(&path, b"keep", 6).unwrap();
            assert!(matches!(
                append(&path, b"too-large", 6).unwrap(),
                super::super::AppendOutcome::RecordTooLarge
            ));
            assert_eq!(fs::read(path).unwrap(), b"keep");
        }
    }
}

#[cfg(all(unix, not(any(target_os = "redox", target_os = "solaris"))))]
pub(super) fn prepare(path: &Path) -> io::Result<()> {
    platform::prepare(path)
}

#[cfg(all(unix, not(any(target_os = "redox", target_os = "solaris"))))]
pub(super) fn append(path: &Path, bytes: &[u8], max_bytes: u64) -> io::Result<AppendOutcome> {
    platform::append(path, bytes, max_bytes)
}

#[cfg(any(not(unix), target_os = "redox", target_os = "solaris"))]
pub(super) fn prepare(_path: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "secure local audit logging is disabled: owner-only ACL/DACL, no-follow ancestry, and file locking cannot be verified on this platform",
    ))
}

#[cfg(any(not(unix), target_os = "redox", target_os = "solaris"))]
pub(super) fn append(_path: &Path, _bytes: &[u8], _max_bytes: u64) -> io::Result<AppendOutcome> {
    prepare(Path::new(""))?;
    unreachable!("unsupported-platform audit preparation always fails")
}
