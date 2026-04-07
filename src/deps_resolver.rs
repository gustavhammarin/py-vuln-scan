use std::collections::HashMap;
use std::str::FromStr;
use std::cell::RefCell;

use pep508_rs::{
    VerbatimUrl, VersionOrUrl,
    pep440_rs::{Operator, Version},
};
use pubgrub::{Dependencies, DependencyProvider, PackageResolutionStatistics, Reporter};
use version_ranges::Ranges;

use crate::error::AppError;
use crate::http::get_requires_dist;
use crate::parsers::parse_deps;

#[derive(serde::Deserialize)]
struct PypiAllVersions {
    releases: HashMap<String, serde_json::Value>,
}

pub struct PyPIProvider {
    client: reqwest::Client,
    runtime: tokio::runtime::Runtime,
    versions_cache: RefCell<HashMap<String, Vec<Version>>>,
    deps_cache: RefCell<HashMap<(String, String), Vec<pep508_rs::Requirement<VerbatimUrl>>>>,
}

impl PyPIProvider {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            runtime: tokio::runtime::Runtime::new().unwrap(),
            versions_cache: RefCell::new(HashMap::new()),
            deps_cache: RefCell::new(HashMap::new()),
        }
    }

    fn fetch_versions(&self, package: &str) -> Vec<Version> {
        if let Some(cached) = self.versions_cache.borrow().get(package) {
            return cached.clone();
        }

        let client = self.client.clone();
        let pkg = package.to_string();

        let versions = match self.runtime.block_on(async move {
            client
                .get(format!("https://pypi.org/pypi/{}/json", pkg))
                .send()
                .await?
                .json::<PypiAllVersions>()
                .await
        }) {
            Ok(resp) => {
                let mut vs: Vec<Version> = resp
                    .releases
                    .keys()
                    .filter_map(|v| Version::from_str(v).ok())
                    .filter(|v| !v.any_prerelease())
                    .collect();
                vs.sort();
                vs
            }
            Err(e) => {
                eprintln!("fetch_versions error ({}): {:?}", package, e);
                vec![]
            }
        };

        self.versions_cache
            .borrow_mut()
            .insert(package.to_string(), versions.clone());
        versions
    }

    fn fetch_deps(
        &self,
        package: &str,
        version: &Version,
    ) -> Vec<pep508_rs::Requirement<VerbatimUrl>> {
        let key = (package.to_string(), version.to_string());

        if let Some(cached) = self.deps_cache.borrow().get(&key) {
            return cached.clone();
        }

        let client = self.client.clone();
        let pkg = package.to_string();
        let ver = version.to_string();

        let deps = match self
            .runtime
            .block_on(async move { get_requires_dist(&client, &pkg, &ver).await })
        {
            Ok(reqs) => parse_deps(reqs),
            Err(_) => vec![],
        };

        self.deps_cache.borrow_mut().insert(key, deps.clone());
        deps
    }
}

fn req_to_range(req: &pep508_rs::Requirement<VerbatimUrl>) -> Ranges<Version> {
    let Some(VersionOrUrl::VersionSpecifier(specs)) = &req.version_or_url else {
        return Ranges::full();
    };

    specs.iter().fold(Ranges::full(), |acc, spec| {
        let v = spec.version().clone();
        let range = match spec.operator() {
            Operator::GreaterThanEqual => Ranges::higher_than(v),
            Operator::GreaterThan => Ranges::strictly_higher_than(v),
            Operator::LessThanEqual => Ranges::lower_than(v),
            Operator::LessThan => Ranges::strictly_lower_than(v),
            Operator::Equal => Ranges::singleton(v),
            Operator::NotEqual => Ranges::singleton(v).complement(),
            Operator::TildeEqual => {
                let upper = bump_compatible(&v);
                Ranges::between(v, upper)
            }
            _ => Ranges::full(),
        };
        acc.intersection(&range)
    })
}

fn bump_compatible(v: &Version) -> Version {
    let mut parts = v.release().to_vec();
    if parts.len() >= 2 {
        parts.pop();
        *parts.last_mut().unwrap() += 1;
    }
    Version::new(parts)
}

impl DependencyProvider for PyPIProvider {
    type P = String;
    type V = Version;
    type VS = Ranges<Version>;
    type M = String;
    type Err = std::convert::Infallible;
    type Priority = usize;

    fn prioritize(
        &self,
        package: &String,
        range: &Ranges<Version>,
        _stats: &PackageResolutionStatistics,
    ) -> usize {
        let count = self
            .fetch_versions(package)
            .iter()
            .filter(|v| range.contains(v))
            .count();
        usize::MAX - count
    }

    fn choose_version(
        &self,
        package: &String,
        range: &Ranges<Version>,
    ) -> Result<Option<Version>, Self::Err> {
        let versions = self.fetch_versions(package);
        Ok(versions.into_iter().rev().find(|v| range.contains(v)))
    }

    fn get_dependencies(
        &self,
        package: &String,
        version: &Version,
    ) -> Result<Dependencies<String, Ranges<Version>, String>, Self::Err> {
        let deps = self.fetch_deps(package, version);

        let map = deps
            .into_iter()
            .map(|req| (req.name.to_string(), req_to_range(&req)))
            .collect();

        Ok(Dependencies::Available(map))
    }
}

#[derive(serde::Serialize, Clone, PartialEq, Eq, Hash)]
pub struct DepRef {
    pub name: String,
    pub version: String,
}

#[derive(serde::Serialize)]
pub struct ResolvedDeps {
    /// Flat map: package name → resolved version string (used for OSV lookups)
    pub packages: HashMap<String, String>,
    /// Adjacency list: package name → direct dependencies with resolved versions
    pub graph: HashMap<String, Vec<DepRef>>,
}

pub async fn resolve_all_deps(
    package: &str,
    version: &str,
) -> Result<ResolvedDeps, AppError> {
    let pkg = package.to_string();
    let ver = version.to_string();

    tokio::task::spawn_blocking(move || {
        let provider = PyPIProvider::new();
        let root_version = Version::from_str(&ver)
            .map_err(|e| AppError::InvalidVersion(e.to_string()))?;

        match pubgrub::resolve(&provider, pkg, root_version) {
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

                let packages = sol.into_iter().map(|(p, v)| (p, v.to_string())).collect();
                Ok(ResolvedDeps { packages, graph })
            }
            Err(pubgrub::PubGrubError::NoSolution(mut tree)) => {
                tree.collapse_no_versions();
                Err(AppError::Resolution(pubgrub::DefaultStringReporter::report(&tree)))
            }
            Err(e) => Err(AppError::Resolution(e.to_string())),
        }
    })
    .await?
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
