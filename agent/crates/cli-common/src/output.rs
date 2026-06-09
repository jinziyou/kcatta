//! JSON output sink shared by the agent binaries.

use std::io::Write;
use std::path::Path;

use anyhow::Context;
use serde::Serialize;

/// Serialize `value` as JSON and write it to `dest` (a file) or stdout when
/// `dest` is `None`. `pretty` selects multi-line vs compact encoding.
///
/// Stdout output gets a trailing newline; a file write logs `wrote <path>` to
/// stderr. This folds the identical stdout/file/pretty blocks the `agent`
/// orchestrator used to duplicate across its `host` and `flow` subcommands.
pub fn write_json<T: Serialize>(
    value: &T,
    dest: Option<&Path>,
    pretty: bool,
) -> anyhow::Result<()> {
    let payload = if pretty {
        serde_json::to_vec_pretty(value)?
    } else {
        serde_json::to_vec(value)?
    };
    match dest {
        Some(path) => {
            std::fs::write(path, &payload)
                .with_context(|| format!("writing {}", path.display()))?;
            eprintln!("wrote {}", path.display());
        }
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(&payload)?;
            stdout.write_all(b"\n")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_compact_and_pretty_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let value = serde_json::json!({"a": 1, "b": [2, 3]});

        let compact = dir.path().join("compact.json");
        write_json(&value, Some(&compact), false).unwrap();
        let compact_text = std::fs::read_to_string(&compact).unwrap();
        assert!(!compact_text.contains('\n'));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&compact_text).unwrap(),
            value
        );

        let pretty = dir.path().join("pretty.json");
        write_json(&value, Some(&pretty), true).unwrap();
        let pretty_text = std::fs::read_to_string(&pretty).unwrap();
        assert!(pretty_text.contains('\n'));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&pretty_text).unwrap(),
            value
        );
    }
}
