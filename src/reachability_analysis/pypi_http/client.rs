use std::{path::PathBuf, sync::Arc};
use tempfile::TempDir;
use crate::reachability_analysis::pypi_http::schemas::PypiResponse;

use crate::{error::AppError};

#[derive(Clone)]
pub struct PypiSourceClient {
    client: Arc<reqwest::Client>,
}

impl PypiSourceClient {
    pub fn new() -> Self {
        Self {
            client: Arc::new(reqwest::Client::new()),
        }
    }
    pub async fn get_source_code(
        &self,
        package_id: &str,
        version: &str,
    ) -> Result<(TempDir, PathBuf), AppError> {
        let sdist_url = self.get_sdist_url(package_id, version).await?;
        let (temp, source_path) =
            self.download_and_extract(package_id, version, &sdist_url).await?;
        Ok((temp, source_path))
    }
    async fn get_sdist_url(
        &self,
        package_id: &str,
        version: &str,
    ) -> Result<String, AppError> {
        let url = format!("https://pypi.org/pypi/{package_id}/{version}/json");
        let resp = self.client.get(url).send().await?.json::<PypiResponse>().await?;

        match resp.get_sdist() {
            Some(u) => Ok(u),
            None => Err(AppError::NotFound("sdist not found".to_string())),
        }
    }

    async fn download_and_extract(
        &self,
        package_id: &str,
        version: &str,
        sdist_url: &str,
    ) -> Result<(TempDir, PathBuf), AppError> {
        let tmp_dir = tempfile::TempDir::new()?;
        let tmp_path = tmp_dir.path().to_path_buf();

        let bytes = self.client.get(sdist_url).send().await?.bytes().await?;

        let tar_path = tmp_dir
            .path()
            .join(format!("{package_id}-{version}.tar.gz"));

        tokio::fs::write(&tar_path, &bytes).await?;

        let tp = tmp_dir.path().to_path_buf();
        tokio::task::spawn_blocking(move || {
            let tar_gz = std::fs::File::open(&tar_path)?;
            let decompressed = flate2::read::GzDecoder::new(tar_gz);
            let mut archive = tar::Archive::new(decompressed);
            archive.unpack(tp)?;
            Ok::<(), AppError>(())
        })
        .await??;

        Ok((tmp_dir, tmp_path))
    }
}




