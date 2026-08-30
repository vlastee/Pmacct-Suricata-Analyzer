//! On-disk spool for batches the server could not accept (offline, restart): one JSON file per
//! batch, bounded in count; oldest are dropped first so the disk cannot fill.
use crate::model::EventsBatch;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub struct Spool {
    dir: PathBuf,
    max_files: usize,
}

impl Spool {
    pub fn new(dir: PathBuf, max_files: usize) -> Self {
        Self { dir, max_files }
    }

    pub fn push(&self, batch: &EventsBatch) -> Result<()> {
        std::fs::create_dir_all(&self.dir).with_context(|| format!("create {}", self.dir.display()))?;
        let mut files = self.files()?;
        while files.len() >= self.max_files {
            let oldest = files.remove(0);
            let _ = std::fs::remove_file(oldest);
        }
        let name = format!("{}-{:06}.json", chrono::Utc::now().format("%Y%m%dT%H%M%S%3f"), std::process::id() % 1_000_000);
        let path = self.dir.join(name);
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec(batch)?)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Oldest spooled batch, if any.
    pub fn peek(&self) -> Result<Option<(PathBuf, EventsBatch)>> {
        for path in self.files()? {
            match std::fs::read(&path).ok().and_then(|raw| serde_json::from_slice::<EventsBatch>(&raw).ok()) {
                Some(b) => return Ok(Some((path, b))),
                None => {
                    let _ = std::fs::remove_file(&path); // corrupt: drop it
                }
            }
        }
        Ok(None)
    }

    pub fn remove(&self, path: &Path) {
        let _ = std::fs::remove_file(path);
    }

    pub fn len(&self) -> usize {
        self.files().map(|f| f.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn files(&self) -> Result<Vec<PathBuf>> {
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&self.dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().map(|x| x == "json").unwrap_or(false) {
                    out.push(p);
                }
            }
        }
        out.sort();
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_bound() {
        let dir = std::env::temp_dir().join(format!("pmacct-agent-spool-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let spool = Spool::new(dir.clone(), 2);
        let batch = |n: u64| EventsBatch { hostname: "h".into(), version: "v".into(), ips: vec![], capture: "poll".into(), dropped: n, conns: vec![] };
        spool.push(&batch(1)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        spool.push(&batch(2)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        spool.push(&batch(3)).unwrap();
        assert_eq!(spool.len(), 2, "oldest dropped");
        let (path, b) = spool.peek().unwrap().unwrap();
        assert_eq!(b.dropped, 2);
        spool.remove(&path);
        assert_eq!(spool.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
