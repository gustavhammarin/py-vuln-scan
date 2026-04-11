//! Implements pubgrub's `DependencyProvider` trait against PyPI.
//!
//! pubgrub is a synchronous library but we live in an async context.
//! Solution: `PyPIProvider` holds a dedicated Tokio runtime and calls
//! `block_on` inside the synchronous provider callbacks.

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
    /// Dedicated runtime for making async HTTP calls from inside
    /// pubgrub's synchronous callbacks.
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

        // Local type — only relevant for this HTTP response.
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
// DependencyProvider implementation
// ---------------------------------------------------------------------------

impl DependencyProvider for PyPIProvider {
    type P = String;
    type V = Version;
    type VS = Ranges<Version>;
    type M = String;
    type Err = std::convert::Infallible;
    type Priority = usize;

    /// Prioritize packages with fewer possible versions — resolves conflicts faster.
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

    /// Choose the newest available version within the allowed range.
    fn choose_version(
        &self,
        package: &String,
        range: &Ranges<Version>,
    ) -> Result<Option<Version>, Self::Err> {
        let versions = self.fetch_versions(package);
        Ok(versions.into_iter().rev().find(|v| range.contains(v)))
    }

    /// Fetch all requirements for a specific package+version and convert to pubgrub ranges.
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
// Version range conversion (PEP 440 → pubgrub Ranges)
// ---------------------------------------------------------------------------

/// Translate a PEP 508 requirement into a pubgrub `Ranges<Version>`.
/// Each operator (>=, ~=, != ...) maps to a Ranges operation.
pub fn req_to_range(req: &pep508_rs::Requirement<VerbatimUrl>) -> Ranges<Version> {
    let Some(VersionOrUrl::VersionSpecifier(specs)) = &req.version_or_url else {
        return Ranges::full(); // no version constraint = all versions allowed
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
                // ~=X.Y means >=X.Y, <X+1 — bump the second-to-last component
                let upper = bump_compatible(&v);
                Ranges::between(v, upper)
            }
            _ => Ranges::full(),
        };
        acc.intersection(&range)
    })
}

/// Compute the upper bound for the `~=` operator.
/// Example: ~=2.3.1 → upper = 2.4.0
fn bump_compatible(v: &Version) -> Version {
    let mut parts = v.release().to_vec();
    if parts.len() >= 2 {
        parts.pop();
        *parts.last_mut().unwrap() += 1;
    }
    Version::new(parts)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use pep508_rs::{Requirement, VerbatimUrl};
    use pep508_rs::pep440_rs::Version;

    use super::req_to_range;

    fn req(s: &str) -> Requirement<VerbatimUrl> {
        Requirement::from_str(s).unwrap()
    }

    fn ver(s: &str) -> Version {
        Version::from_str(s).unwrap()
    }

    #[test]
    fn no_version_constraint_allows_all() {
        let range = req_to_range(&req("requests"));
        assert!(range.contains(&ver("1.0")));
        assert!(range.contains(&ver("99.0")));
    }

    #[test]
    fn gte_includes_exact_and_higher() {
        let range = req_to_range(&req("requests>=2.0"));
        assert!(range.contains(&ver("2.0")));
        assert!(range.contains(&ver("3.0")));
        assert!(!range.contains(&ver("1.9")));
    }

    #[test]
    fn gt_excludes_exact_version() {
        let range = req_to_range(&req("requests>2.0"));
        assert!(!range.contains(&ver("2.0")));
        assert!(range.contains(&ver("2.1")));
    }

    #[test]
    fn lte_includes_exact_and_lower() {
        let range = req_to_range(&req("requests<=2.0"));
        assert!(range.contains(&ver("2.0")));
        assert!(range.contains(&ver("1.0")));
        assert!(!range.contains(&ver("2.1")));
    }

    #[test]
    fn lt_excludes_exact_version() {
        let range = req_to_range(&req("requests<2.0"));
        assert!(!range.contains(&ver("2.0")));
        assert!(range.contains(&ver("1.9")));
    }

    #[test]
    fn eq_is_singleton() {
        let range = req_to_range(&req("requests==2.0"));
        assert!(range.contains(&ver("2.0")));
        assert!(!range.contains(&ver("2.1")));
        assert!(!range.contains(&ver("1.9")));
    }

    #[test]
    fn neq_excludes_exact_allows_others() {
        let range = req_to_range(&req("requests!=2.0"));
        assert!(!range.contains(&ver("2.0")));
        assert!(range.contains(&ver("1.9")));
        assert!(range.contains(&ver("2.1")));
    }

    #[test]
    fn compatible_release_two_parts() {
        // ~=2.3 means >=2.3, <3.0  (bump_compatible([2,3]) = [3])
        let range = req_to_range(&req("requests~=2.3"));
        assert!(range.contains(&ver("2.3")));
        assert!(range.contains(&ver("2.9")));
        assert!(!range.contains(&ver("3.0")));
        assert!(!range.contains(&ver("2.2")));
    }

    #[test]
    fn compatible_release_three_parts() {
        // ~=2.3.1 means >=2.3.1, <2.4.0  (bump_compatible([2,3,1]) = [2,4])
        let range = req_to_range(&req("requests~=2.3.1"));
        assert!(range.contains(&ver("2.3.1")));
        assert!(range.contains(&ver("2.3.9")));
        assert!(!range.contains(&ver("2.4.0")));
        assert!(!range.contains(&ver("2.3.0")));
    }

    #[test]
    fn multiple_constraints_are_intersected() {
        let range = req_to_range(&req("requests>=1.0,<3.0"));
        assert!(range.contains(&ver("1.0")));
        assert!(range.contains(&ver("2.9")));
        assert!(!range.contains(&ver("0.9")));
        assert!(!range.contains(&ver("3.0")));
    }

    #[test]
    fn conflicting_constraints_produce_empty_range() {
        // >=3.0 AND <2.0 — no version satisfies both
        let range = req_to_range(&req("requests>=3.0,<2.0"));
        assert!(range.is_empty());
    }
}
