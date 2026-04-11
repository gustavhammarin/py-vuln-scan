mod parsers;
mod provider;
pub mod pypi;

use std::{collections::HashMap, str::FromStr};

use pep508_rs::pep440_rs::Version;
use pubgrub::Reporter;

use crate::error::AppError;
use provider::PyPIProvider;

// ---------------------------------------------------------------------------
// Publika typer
// ---------------------------------------------------------------------------

/// En direkt beroendekant: ett paket med upplöst version.
#[derive(serde::Serialize, Clone, PartialEq, Eq, Hash, Debug)]
pub struct DepRef {
    pub name: String,
    pub version: String,
}

/// Resultatet av en full dependency-resolution.
pub struct ResolvedDeps {
    /// Flat map: paketnamn → upplöst version (används för OSV-lookups).
    pub packages: HashMap<String, String>,
    /// Adjacency-lista: paketnamn → direkta beroenden med upplösta versioner.
    pub graph: HashMap<String, Vec<DepRef>>,
}

// ---------------------------------------------------------------------------
// Publik ingångspunkt
// ---------------------------------------------------------------------------

/// Löser transitiva beroenden för ett PyPI-paket via pubgrub.
pub struct DepsResolver;

impl DepsResolver {
    pub fn new() -> Self {
        Self
    }

    /// Lös alla transitiva beroenden och returnera ett platt paket-map
    /// samt en adjacency-lista.
    pub async fn resolve(&self, package: &str, version: &str) -> Result<ResolvedDeps, AppError> {
        let pkg = package.to_string();
        let ver = version.to_string();

        tokio::task::spawn_blocking(move || {
        let provider = PyPIProvider::new();
        let root_version =
            Version::from_str(&ver).map_err(|e| AppError::InvalidVersion(e.to_string()))?;

        match pubgrub::resolve(&provider, pkg.clone(), root_version) {
            Ok(sol) => {
                let mut graph: HashMap<String, Vec<DepRef>> = HashMap::new();

                for (pkg, ver) in &sol {
                    let key = (pkg.clone(), ver.to_string());
                    let deps = provider
                        .deps_cache
                        .borrow()
                        .get(&key)
                        .map(|deps| {
                            let mut seen = std::collections::HashSet::new();
                            deps.iter()
                                .filter_map(|req| {
                                    let name = req.name.to_string();
                                    let version = sol.get(&name)?.to_string();
                                    let node = DepRef { name, version };
                                    seen.insert(node.clone()).then_some(node)
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    graph.insert(pkg.clone(), deps);
                }

                let packages: HashMap<String, String> =
                    sol.into_iter().map(|(p, v)| (p, v.to_string())).collect();

                Ok(ResolvedDeps { packages, graph })
            }
            Err(pubgrub::PubGrubError::NoSolution(mut tree)) => {
                tree.collapse_no_versions();
                Err(AppError::Resolution(
                    pubgrub::DefaultStringReporter::report(&tree),
                ))
            }
            Err(e) => Err(AppError::Resolution(e.to_string())),
        }
        })
        .await?
    }
}


#[test]
fn test_resolve() {
    let provider = PyPIProvider::new();
    let root_version = Version::from_str("4.0.2").unwrap();

    match pubgrub::resolve(&provider, "twine".to_string(), root_version) {
        Ok(sol) => {
            for (pkg, ver) in &sol {
                println!("{} == {}", pkg, ver);
            }
        }
        Err(pubgrub::PubGrubError::NoSolution(mut tree)) => {
            tree.collapse_no_versions();
            eprintln!("{}", pubgrub::DefaultStringReporter::report(&tree));
        }
        Err(e) => eprintln!("{:?}", e),
    }
}
