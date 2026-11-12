use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub struct Ctx {
    pub dry_run: bool,
    pub verbose: bool,
    pub conf_dir: PathBuf,
    // none = stdout
    pub log: Option<Arc<Mutex<String>>>,
    // none = search desktops
    pub readme: Option<String>,
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

    pub fn ask(&self, q: &str) -> Option<bool> {
        if self.dry_run {
            self.info(format!("[dry-run] would ask: {q}"));
            return None;
        }
        #[cfg(windows)]
        if self.log.is_some() {
            let a = crate::gui::ask(q);
            self.info(format!("{q} -> {}", match a { Some(true) => "y", Some(false) => "n", None => "skipped" }));
            return a;
        }
        // may lack stdin handle
        #[cfg(windows)]
        let input = std::fs::OpenOptions::new().read(true).write(true).open("CONIN$").ok()?;
        #[cfg(not(windows))]
        let input = std::io::stdin();
        let mut input = std::io::BufReader::new(input);
        loop {
            print!("[?] {q} [y/n] ");
            std::io::Write::flush(&mut std::io::stdout()).ok()?;
            let mut line = String::new();
            if std::io::BufRead::read_line(&mut input, &mut line).ok()? == 0 {
                return None;
            }
            match line.trim().to_ascii_lowercase().as_str() {
                "y" | "yes" => return Some(true),
                "n" | "no" => return Some(false),
                _ => {}
            }
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
