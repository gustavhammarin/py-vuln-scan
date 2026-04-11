//! Implementerar pubgrubs `DependencyProvider`-trait mot PyPI.
//!
//! pubgrub är ett synkront bibliotek men vi lever i en async-värld.
//! Lösningen: `PyPIProvider` håller en dedikerad Tokio-runtime och
//! anropar `block_on` inifrån de synkrona provider-callbacks.

use std::{cell::RefCell, collections::HashMap, str::FromStr};

use pep508_rs::{
    VerbatimUrl, VersionOrUrl,
    pep440_rs::{Operator, Version},
};
use pubgrub::{Dependencies, DependencyProvider, PackageResolutionStatistics};
use version_ranges::Ranges;

use super::parsers::parse_deps;
use super::pypi::client::get_requires_dist;

// ---------------------------------------------------------------------------
// Struct
// ---------------------------------------------------------------------------

pub struct PyPIProvider {
    pub client: reqwest::Client,
    /// Dedikerad runtime för att kunna köra async HTTP-anrop inifrån
    /// pubgrubs synkrona callbacks.
    pub runtime: tokio::runtime::Runtime,
    pub versions_cache: RefCell<HashMap<String, Vec<Version>>>,
    pub deps_cache: RefCell<HashMap<(String, String), Vec<pep508_rs::Requirement<VerbatimUrl>>>>,
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

    pub fn fetch_versions(&self, package: &str) -> Vec<Version> {
        if let Some(cached) = self.versions_cache.borrow().get(package) {
            return cached.clone();
        }

        // Lokal typ — bara relevant för denna HTTP-respons.
        #[derive(serde::Deserialize)]
        struct AllVersions {
            releases: HashMap<String, serde_json::Value>,
        }

        let client = self.client.clone();
        let pkg = package.to_string();

        let versions = match self.runtime.block_on(async move {
            client
                .get(format!("https://pypi.org/pypi/{}/json", pkg))
                .send()
                .await?
                .json::<AllVersions>()
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

    pub fn fetch_deps(
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

// ---------------------------------------------------------------------------
// DependencyProvider-implementationen
// ---------------------------------------------------------------------------

impl DependencyProvider for PyPIProvider {
    type P = String;
    type V = Version;
    type VS = Ranges<Version>;
    type M = String;
    type Err = std::convert::Infallible;
    type Priority = usize;

    /// Prioritera paket med färre möjliga versioner — löser konflikter snabbare.
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

    /// Välj den senaste tillgängliga versionen inom det tillåtna spannet.
    fn choose_version(
        &self,
        package: &String,
        range: &Ranges<Version>,
    ) -> Result<Option<Version>, Self::Err> {
        let versions = self.fetch_versions(package);
        Ok(versions.into_iter().rev().find(|v| range.contains(v)))
    }

    /// Hämta alla krav för en specifik paket+version och konvertera till pubgrub-ranges.
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

// ---------------------------------------------------------------------------
// Versionsspann-konvertering (PEP 440 → pubgrub Ranges)
// ---------------------------------------------------------------------------

/// Översätt ett PEP 508-krav till ett pubgrub `Ranges<Version>`.
/// Varje operator (>=, ~=, != ...) mappas till en Ranges-operation.
pub fn req_to_range(req: &pep508_rs::Requirement<VerbatimUrl>) -> Ranges<Version> {
    let Some(VersionOrUrl::VersionSpecifier(specs)) = &req.version_or_url else {
        return Ranges::full(); // inget versionskrav = alla versioner tillåtna
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
                // ~=X.Y betyder >=X.Y, <X+1 — dvs bump den näst sista komponenten
                let upper = bump_compatible(&v);
                Ranges::between(v, upper)
            }
            _ => Ranges::full(),
        };
        acc.intersection(&range)
    })
}

/// Beräkna övre gränsen för `~=`-operatorn.
/// Exempel: ~=2.3.1 → upper = 2.4.0
fn bump_compatible(v: &Version) -> Version {
    let mut parts = v.release().to_vec();
    if parts.len() >= 2 {
        parts.pop();
        *parts.last_mut().unwrap() += 1;
    }
    Version::new(parts)
}
