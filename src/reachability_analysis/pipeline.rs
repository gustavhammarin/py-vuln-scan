use std::{collections::HashMap, path::PathBuf};

use serde::Serialize;

use crate::{
    dep_graph::graph::DepNode,
    error::AppError,
    reachability_analysis::{
        code_analyser::analyzer::{CodeAnalyzer, Finding},
        source_code_fetcher::client::SourceCodeFetcher,
    },
};

#[derive(Debug, Clone, Serialize)]
pub struct VulnChainAnalysis {
    pub chain: Vec<DepNode>,
    pub findings: Vec<Finding>,
}

pub async fn analyze_source(
    vuln_chains: &Vec<Vec<DepNode>>,
) -> Result<Vec<VulnChainAnalysis>, AppError> {
    let client = SourceCodeFetcher::new();
    let temp = tempfile::TempDir::new().unwrap();
    let tmp_dir = temp.path();

    //skapa cache lookup hashset om det finns ta här i från annars hämta,

    let mut source_cache: HashMap<(String, String), PathBuf> = HashMap::new();

    let mut results: Vec<VulnChainAnalysis> = Vec::new();

    //loopa igenom vuln chain och ta två åt gången den första är from den efter är to , jämför med package name från den först

    for chain in vuln_chains {
        let mut chain_findings = Vec::new();

        for window in chain.windows(2) {
            let dep_to_track = &window[0];
            let target_dep = &window[1];

            let key = (target_dep.package_id.clone(), target_dep.version.clone());

            let source_dir = if let Some(dir) = source_cache.get(&key) {
                dir.clone()
            } else {
                let dir = client
                    .get_source_code(&target_dep.package_id, &target_dep.version, tmp_dir)
                    .await?;
                println!("fetched dir: {:?}", dir);
                source_cache.insert(key, dir.clone());
                dir
            };

            let analyzer = CodeAnalyzer::new(dep_to_track, target_dep, &source_dir)?;
            let findings = analyzer.analyze()?;

            chain_findings.extend(findings);
        }
        results.push(VulnChainAnalysis {
            chain: chain.clone(),
            findings: chain_findings,
        });
    }

    Ok(results)
}
