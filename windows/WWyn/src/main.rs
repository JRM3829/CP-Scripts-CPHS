//! cli -> Ctx -> module. no args on windows -> gui
#![cfg_attr(windows, windows_subsystem = "windows")]
mod ctx;
#[cfg(windows)]
mod gui;
mod modules;
mod readme;
mod sys;

use clap::Parser;

#[derive(Parser)]
#[command(name = "wyn", about = "CyberPatriot Windows hardening (applies changes unless --dry-run)")]
struct Cli {
    /// module to run (see list below when omitted)
    module: Option<String>,
    /// preview changes without making them
    #[arg(short, long)]
    dry_run: bool,
    #[arg(short, long)]
    verbose: bool,
    /// README url or file, instead of searching the Desktops
    #[arg(long)]
    readme: Option<String>,
}

fn main() -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        if std::env::args().len() == 1 {
            return gui::main();
        }
        gui::attach_console();
    }
    let cli = Cli::parse();
    let Some(name) = cli.module else {
        println!("modules:");
        for (n, _) in modules::ALL {
            println!("  {n}");
        }
        return Ok(());
    };
    let Some((_, run)) = modules::ALL.iter().find(|(n, _)| *n == name) else {
        anyhow::bail!("unknown module '{name}'");
    };
    let mut ctx = ctx::Ctx::new(cli.dry_run, cli.verbose);
    ctx.readme = cli.readme;
    run(&ctx)
}
