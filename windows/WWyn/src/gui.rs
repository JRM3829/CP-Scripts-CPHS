//! elevate via UAC, then one window: pick module, Run, see output
use crate::{
    ctx::{Ctx, Progress},
    modules,
};
use eframe::egui;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

#[link(name = "shell32")]
extern "system" {
    fn IsUserAnAdmin() -> i32;
    fn ShellExecuteW(hwnd: isize, op: *const u16, file: *const u16, args: *const u16, dir: *const u16, show: i32) -> isize;
}
#[link(name = "user32")]
extern "system" {
    fn MessageBoxW(hwnd: isize, text: *const u16, caption: *const u16, kind: u32) -> i32;
}
#[link(name = "kernel32")]
extern "system" {
    fn AttachConsole(pid: u32) -> i32;
}

fn w(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

/// gui subsystem has no console; borrow the parent's so the cli still prints
pub fn attach_console() {
    unsafe { AttachConsole(u32::MAX) }; // ATTACH_PARENT_PROCESS
}

pub fn main() -> anyhow::Result<()> {
    if unsafe { IsUserAnAdmin() } == 0 {
        // runas starts in System32; pass our cwd so ./conf is still found
        let (exe, dir) = (std::env::current_exe()?, std::env::current_dir()?);
        let r = unsafe {
            ShellExecuteW(0, w("runas").as_ptr(), w(&exe.to_string_lossy()).as_ptr(), std::ptr::null(), w(&dir.to_string_lossy()).as_ptr(), 1)
        };
        if r <= 32 {
            unsafe { MessageBoxW(0, w("UAC is required").as_ptr(), w("wyn").as_ptr(), 0x10) }; // MB_ICONERROR
        }
        return Ok(());
    }
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([450.0, 420.0]),
        ..Default::default()
    };
    let app = App { module: 0, dry_run: false, readme: String::new(), out: modules::ALL.iter().map(|_| Default::default()).collect(), running: 0, progress: Default::default(), job: None };
    eframe::run_native("wyn", opts, Box::new(|_| Ok(Box::new(app)))).map_err(|e| anyhow::anyhow!("{e}"))
}

struct App {
    module: usize,
    dry_run: bool,
    readme: String,
    /// one log per module, same order as modules::ALL
    out: Vec<Arc<Mutex<String>>>,
    running: usize,
    progress: Arc<Mutex<Option<Progress>>>,
    job: Option<JoinHandle<()>>,
}

fn label(name: &str) -> &str {
    match name {
        "menial" => "Hardening",
        "users" => "Users",
        "updates" => "Updates",
        n => n,
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _: &mut eframe::Frame) {
        let busy = self.job.as_ref().is_some_and(|j| !j.is_finished());
        if busy {
            ui.ctx().request_repaint_after(std::time::Duration::from_millis(100));
        }
        egui::CentralPanel::default().show(ui, |ui| {
            ui.heading("wyn");
            ui.separator();
            ui.label("Select module:");
            ui.horizontal(|ui| {
                for (i, (n, _)) in modules::ALL.iter().enumerate() {
                    ui.selectable_value(&mut self.module, i, label(n));
                }
            });
            let (name, run) = modules::ALL[self.module];
            ui.label(format!("{}:", label(name)));
            if name == "users" {
                ui.horizontal(|ui| {
                    ui.label("Manual README URL:");
                    ui.add(egui::TextEdit::singleline(&mut self.readme).hint_text("Only put a link here if autosearch for README fails").desired_width(f32::INFINITY));
                });
            }
            ui.horizontal(|ui| {
                if ui.add_enabled(!busy, egui::Button::new("Run")).clicked() {
                    let mut ctx = Ctx::new(self.dry_run, false);
                    ctx.log = Some(self.out[self.module].clone());
                    self.running = self.module;
                    ctx.progress = self.progress.clone();
                    *self.progress.lock().unwrap() = None;
                    ctx.readme = Some(self.readme.trim().to_string()).filter(|s| !s.is_empty());
                    ctx.emit(format!("--- {name}{} ---", if self.dry_run { " (dry run)" } else { "" }));
                    self.job = Some(std::thread::spawn(move || match run(&ctx) {
                        Ok(()) => ctx.emit("done.".into()),
                        Err(e) => ctx.emit(format!("error: {e:#}")),
                    }));
                }
                if ui.button("Clear").clicked() {
                    self.out[self.module].lock().unwrap().clear();
                }
                ui.checkbox(&mut self.dry_run, "Dry run");
            });
            if let (true, true, Some(p)) = (busy, self.module == self.running, &*self.progress.lock().unwrap()) {
                // timer climbing on one item = stuck
                let text = format!("{}/{}  {}  {}s", p.done + 1, p.total, p.item, p.since.elapsed().as_secs());
                ui.add(egui::ProgressBar::new(p.done as f32 / p.total as f32).text(text));
            }
            ui.label("Output:");
            egui::ScrollArea::vertical().stick_to_bottom(true).auto_shrink(false).show(ui, |ui| {
                let mut text = self.out[self.module].lock().unwrap().clone();
                ui.add(egui::TextEdit::multiline(&mut text).code_editor().desired_width(f32::INFINITY).interactive(true));
            });
        });
    }
}
