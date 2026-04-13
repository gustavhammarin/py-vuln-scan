use std::collections::HashMap;

use clap::Parser;
use pypi_scanner::{
    dep_graph::graph::DepGraph,
    deps_resolver::DepsResolver,
    error::AppError,
    osv::{OsvVuln, VulnFetcher},
    reachability_analysis,
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
    let deps = DepsResolver::new()
        .resolve(&cli.package, &cli.version)
        .await?;

    println!("Checking for vulnerabilities...");
    let vulns = VulnFetcher::new()
        .fetch_vulnerabilities(deps.packages.clone())
        .await?;

    let vuln_map = osv_vulns_to_map(vulns.clone());

    let graph = DepGraph::build_graph(deps.graph, vuln_map);

    let json_string = graph.to_json().unwrap();

    let chains = graph.find_all_vulnerable_chains(&cli.package);

    let code_analysis_result = reachability_analysis::pipeline::analyze_source(&chains).await?;

    tokio::fs::write(
        "code_analysis.json",
        serde_json::to_string_pretty(&code_analysis_result).unwrap(),
    )
    .await
    .unwrap();

    tokio::fs::write("result.json", json_string).await.unwrap();

    tokio::fs::write("vulns.json", serde_json::to_string_pretty(&vulns).unwrap())
        .await
        .unwrap();
    tokio::fs::write(
        "vuln_chains.json",
        serde_json::to_string_pretty(&chains).unwrap(),
    )
    .await
    .unwrap();

    Ok(())
}

fn osv_vulns_to_map(vulns: Vec<(String, Vec<OsvVuln>)>) -> HashMap<String, Vec<String>> {
    vulns
        .into_iter()
        .map(|(package, vulns)| {
            let ids = vulns.into_iter().map(|v| v.id).collect();
            (package, ids)
        })
        .collect()
}
