mod error;
mod http;
mod parsers;
mod deps_resolver;
mod osv;
mod schemas;
mod tui;

use clap::Parser;
use crossterm::event::{self, Event, KeyCode};

use crate::{deps_resolver::resolve_all_deps, error::AppError, osv::VulnFetcher, tui::{App, draw}};

#[derive(Parser)]
#[command(name = "pypi-scanner")]
#[command(about = "Scanning PyPI-packages for vulnerabilities")]
struct Cli {
    package: String,
    version: String,
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let cli = Cli::parse();

    println!("Gathering data...");
    let deps = resolve_all_deps(&cli.package, &cli.version).await?;
    /* tokio::fs::write("result.json", serde_json::to_string_pretty(&deps).unwrap()).await.unwrap();  */
    println!("Checking for vulnerabilities...");
    let vuln_fetcher = VulnFetcher::new();
    let vulns = vuln_fetcher.fetch_vulnerabilities(deps.packages).await?;

    /* tokio::fs::write("vulns.json", serde_json::to_string_pretty(&vulns).unwrap()).await.unwrap();  */

    let mut terminal = ratatui::init();
    let mut app = App::new(vulns);

    loop {
        terminal.draw(|f| draw(f, &mut app))?;

        if let Event::Key(key) = event::read()? {
            match key.code {
                KeyCode::Down | KeyCode::Char('j') => app.next(),
                KeyCode::Up   | KeyCode::Char('k') => app.prev(),
                KeyCode::Char('q') | KeyCode::Esc  => break,
                _ => {}
            }
        }
    }

    ratatui::restore();
    Ok(())
}
