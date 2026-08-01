#![forbid(unsafe_code)]
use std::{
    env, fs,
    path::{Path, PathBuf},
};

fn inventory(root: &Path) -> std::io::Result<Vec<(String, u64, bool)>> {
    let mut pending = vec![root.to_path_buf()];
    let mut rows = Vec::new();
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        let relative = path.strip_prefix(root).unwrap_or(Path::new("."));
        rows.push((
            relative.display().to_string(),
            metadata.len(),
            metadata.permissions().readonly(),
        ));
        if metadata.is_dir() {
            let mut children = fs::read_dir(&path)?
                .filter_map(Result::ok)
                .map(|e| e.path())
                .collect::<Vec<PathBuf>>();
            children.sort();
            pending.extend(children.into_iter().rev());
        }
    }
    Ok(rows)
}
fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os();
    let _program = args.next();
    let root = args
        .next()
        .ok_or("usage: kernaid-linux-inventory <fixture-directory>")?;
    if args.next().is_some() {
        return Err("exactly one fixture directory is required".into());
    }
    let root = PathBuf::from(root);
    if !root.is_dir() {
        return Err("target must be a directory fixture".into());
    }
    let rows = inventory(&root)?;
    print!("{{\"schemaVersion\":\"1.0\",\"trust\":\"observed-untrusted\",\"entries\":[");
    for (i, (path, size, readonly)) in rows.iter().enumerate() {
        if i > 0 {
            print!(",");
        }
        print!(
            "{{\"path\":\"{}\",\"size\":{},\"readonly\":{}}}",
            escape(path),
            size,
            readonly
        );
    }
    println!("]}}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn escaping_preserves_json() {
        assert_eq!(escape("a\"b"), "a\\\"b");
    }
}
