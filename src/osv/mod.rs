mod schemas;

// Re-export the types the rest of the app needs to reference.
pub use schemas::{
    OsvAffected, OsvAffectedPackage, OsvEvent, OsvRange, OsvReference, OsvSeverity, OsvVuln,
};

use std::collections::HashMap;

use futures::{StreamExt, stream};

use crate::error::AppError;
use schemas::{OsvPackage, OsvQuery, OsvResponse};

/// Fetches vulnerabilities from the OSV database for a set of packages in parallel.
pub struct VulnFetcher {
    client: reqwest::Client,
}

impl VulnFetcher {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    /// Look up all vulnerabilities for an entire dependency list.
    /// Runs up to 10 HTTP requests in parallel.
    pub async fn fetch_vulnerabilities(
        &self,
        packages: HashMap<String, String>,
    ) -> Result<Vec<(String, Vec<OsvVuln>)>, AppError> {
        let results = stream::iter(packages)
            .map(|(p, v)| async move { self.fetch_vulns_for_package(&p, &v).await })
            .buffer_unordered(10)
            .filter_map(|r| async { r.ok() })
            .collect::<Vec<_>>()
            .await;

        Ok(results)
    }

    pub async fn fetch_vulns_for_package(
        &self,
        name: &str,
        version: &str,
    ) -> Result<(String, Vec<OsvVuln>), AppError> {
        let query = OsvQuery {
            package: OsvPackage {
                name: name.to_string(),
                ecosystem: "PyPI".to_string(),
            },
            version: version.to_string(),
        };

        let response: OsvResponse = self
            .client
            .post("https://api.osv.dev/v1/query")
            .json(&query)
            .send()
            .await?
            .json()
            .await?;

        Ok((name.to_string(), response.vulns.unwrap_or_default()))
    }
}
// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_input_returns_empty() {
        let vulns = VulnFetcher::new()
            .fetch_vulnerabilities(HashMap::new())
            .await
            .unwrap();
        assert!(vulns.is_empty());
    }

    #[tokio::test]
    async fn known_vulnerable_package_returns_vulns() {
        // requests 2.6.0 has a well-known credential-exposure vulnerability
        let mut packages = HashMap::new();
        packages.insert("requests".to_string(), "2.6.0".to_string());

        let vulns = VulnFetcher::new()
            .fetch_vulnerabilities(packages)
            .await
            .unwrap();

        assert!(
            !vulns.is_empty(),
            "requests 2.6.0 should have known vulnerabilities"
        );
    }

    #[tokio::test]
    async fn each_vuln_has_a_non_empty_id() {
        let mut packages = HashMap::new();
        packages.insert("requests".to_string(), "2.6.0".to_string());

        let res = VulnFetcher::new()
            .fetch_vulnerabilities(packages)
            .await
            .unwrap();

        for (_, o) in &res {
            for v in o {
                assert!(!v.id.is_empty())
            }
        }
    }
}
