use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// dry_run is enforced in sys.rs, not by modules
pub struct Ctx {
    pub dry_run: bool,
    pub verbose: bool,
    pub conf_dir: PathBuf,
    /// gui sets this; None prints to stdout
    pub log: Option<Arc<Mutex<String>>>,
    /// README url or file; None searches the Desktops
    pub readme: Option<String>,
    /// long steps report here; gui shows it as a bar with a timer
    pub progress: Arc<Mutex<Option<Progress>>>,
}

#[cfg_attr(not(windows), allow(dead_code))] // only the windows gui reads it
pub struct Progress {
    pub done: usize,
    pub total: usize,
    pub item: String,
    pub since: Instant,
}

impl Ctx {
    pub fn new(dry_run: bool, verbose: bool) -> Self {
        let home = std::env::var_os("WYN_HOME").map(PathBuf::from).unwrap_or_default();
        Ctx { dry_run, verbose, conf_dir: home.join("conf"), log: None, readme: None, progress: Default::default() }
    }

    pub fn info(&self, msg: impl AsRef<str>) {
        self.emit(format!("[*] {}", msg.as_ref()));
    }

    pub fn debug(&self, msg: impl AsRef<str>) {
        if self.verbose {
            self.emit(format!("    {}", msg.as_ref()));
        }
    }

    pub fn emit(&self, line: String) {
        match &self.log {
            Some(l) => *l.lock().unwrap() += &(line + "\n"),
            None => println!("{line}"),
        }
    }

    pub fn set_progress(&self, done: usize, total: usize, item: &str) {
        *self.progress.lock().unwrap() = Some(Progress { done, total, item: item.into(), since: Instant::now() });
    }

    pub fn load<T: serde::de::DeserializeOwned>(&self, file: &str) -> anyhow::Result<T> {
        let p = self.conf_dir.join(file);
        let s = std::fs::read_to_string(&p).map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))?;
        toml::from_str(&s).map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))
    }
}
