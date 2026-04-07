mod deps_resolver;
mod error;
mod http;
mod osv;
mod parsers;
mod schemas;
mod tui;

use std::{collections::{HashMap, HashSet}};

use clap::Parser;
use crossterm::event::{self, Event, KeyCode};

use crate::{
    deps_resolver::{DepRef, resolve_all_deps},
    error::AppError,
    osv::VulnFetcher,
    schemas::OsvVuln,
    tui::{App, draw},
};

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

    let mut visited: HashSet<String> = HashSet::new();

    let tree = sort_graph(&cli.package, &cli.version, &deps.graph, &vulns, &mut visited);

    tokio::fs::write("vulns.json", serde_json::to_string_pretty(&tree).unwrap()).await.unwrap();

    let mut terminal = ratatui::init();
    let mut app = App::new(vulns);

    loop {
        terminal.draw(|f| draw(f, &mut app))?;

        if let Event::Key(key) = event::read()? {
            match key.code {
                KeyCode::Down | KeyCode::Char('j') => app.next(),
                KeyCode::Up | KeyCode::Char('k') => app.prev(),
                KeyCode::Char('q') | KeyCode::Esc => break,
                _ => {}
            }
        }
    }

    ratatui::restore();
    Ok(())
}

#[derive(serde::Serialize, Clone)]
pub struct PackageRef {
    pub name: String,
    pub version: String,
    pub depends_on: Vec<Box<PackageRef>>,
    pub vulns: Vec<OsvVuln>,
}

pub fn sort_graph(
    root: &str,
    root_ver: &str,
    unsorted: &HashMap<String, Vec<DepRef>>,
    vulns: &Vec<OsvVuln>,
    visited: &mut HashSet<String>,
) -> PackageRef {
    let key = format!("{}@{}", root, root_ver);

    let pkg_specific_vulns: Vec<_> = vulns
        .iter()
        .filter(|entry| {
            entry
                .affected
                .as_ref()
                .and_then(|f| {
                    f.iter().find(|a| {
                        a.package
                            .as_ref()
                            .map(|p| p.name.as_str())
                            .is_some_and(|name| name.eq_ignore_ascii_case(&root))
                    })
                })
                .is_some()
        })
        .cloned().collect();

    if !visited.insert(key) {
        return PackageRef {
            name: root.to_string(),
            version: root_ver.to_string(),
            depends_on: vec![],
            vulns: pkg_specific_vulns
        };
    }

    let deps = unsorted.get(root).cloned().unwrap_or_default();

    PackageRef {
        name: root.to_string(),
        version: root_ver.to_string(),
        depends_on: deps
            .iter()
            .map(|dep| Box::new(sort_graph(&dep.name, &dep.version, unsorted, vulns, visited)))
            .collect(),
        vulns: pkg_specific_vulns
    }
}
