mod dep_graph;
mod deps_resolver;
mod error;
mod osv;
mod reachability_analysis;
mod tui;

use clap::Parser;

use crate::{
    dep_graph::DepNode,
    deps_resolver::DepsResolver,
    error::AppError,
    osv::VulnFetcher,
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
    let deps = DepsResolver::new().resolve(&cli.package, &cli.version).await?;

    println!("Checking for vulnerabilities...");
    let vulns = VulnFetcher::new()
        .fetch_vulnerabilities(deps.packages.clone())
        .await?;

    let tree = DepNode::build(
        &cli.package,
        deps.packages.get(&cli.package).unwrap(),
        &deps.graph,
        &vulns,
    );
    
    let chains = tree.vuln_chains();

    tokio::fs::write("result.json", serde_json::to_string_pretty(&tree).unwrap())
        .await
        .unwrap();

    tokio::fs::write("vulns.json", serde_json::to_string_pretty(&vulns).unwrap())
        .await
        .unwrap();
    tokio::fs::write("vuln_chains.json", serde_json::to_string_pretty(&chains).unwrap())
        .await
        .unwrap();

    Ok(())
}
