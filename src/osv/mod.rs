mod schemas;

// Re-exportera de typer som resten av appen behöver känna till.
pub use schemas::OsvVuln;

use std::collections::HashMap;

use futures::{StreamExt, stream};

use crate::error::AppError;
use schemas::{OsvPackage, OsvQuery, OsvResponse};

/// Hämtar sårbarheter från OSV-databasen för en mängd paket parallellt.
pub struct VulnFetcher {
    client: reqwest::Client,
}

impl VulnFetcher {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    /// Slå upp alla sårbarheter för en hel dependency-lista.
    /// Kör upp till 10 HTTP-anrop parallellt.
    pub async fn fetch_vulnerabilities(
        &self,
        packages: HashMap<String, String>,
    ) -> Result<Vec<OsvVuln>, AppError> {
        let results = stream::iter(packages)
            .map(|(p, v)| self.fetch_vulns_for_package(p, v))
            .buffer_unordered(10)
            .filter_map(|r| async { r.ok() })
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .flatten()
            .collect();

        Ok(results)
    }

    async fn fetch_vulns_for_package(
        &self,
        name: String,
        version: String,
    ) -> Result<Vec<OsvVuln>, AppError> {
        let query = OsvQuery {
            package: OsvPackage {
                name,
                ecosystem: "PyPI".to_string(),
            },
            version,
        };

        let response: OsvResponse = self
            .client
            .post("https://api.osv.dev/v1/query")
            .json(&query)
            .send()
            .await?
            .json()
            .await?;

        Ok(response.vulns.unwrap_or_default())
    }
}
