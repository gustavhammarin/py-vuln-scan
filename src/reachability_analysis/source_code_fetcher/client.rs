use std::path::Path;
use std::{path::PathBuf, sync::Arc};
use tempfile::TempDir;
use crate::reachability_analysis::source_code_fetcher::schemas::PypiResponse;

use crate::{error::AppError};

#[derive(Clone)]
pub struct SourceCodeFetcher {
    client: Arc<reqwest::Client>,
}

impl SourceCodeFetcher {
    pub fn new() -> Self {
        Self {
            client: Arc::new(reqwest::Client::new()),
        }
    }
    pub async fn get_source_code(
        &self,
        package_id: &str,
        version: &str,
        tmp_dir: &Path,
    ) -> Result<PathBuf, AppError> {
        let sdist_url = self.get_sdist_url(package_id, version).await?;
        let source_path =
            self.download_and_extract(package_id, version, &sdist_url, tmp_dir).await?;
        Ok(source_path)
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
        tmp_dir: &Path
    ) -> Result<PathBuf, AppError> {

        let bytes = self.client.get(sdist_url).send().await?.bytes().await?;

        let tar_path = tmp_dir
            .join(format!("{package_id}-{version}.tar.gz"));

        tokio::fs::write(&tar_path, &bytes).await?;

        let extract_dir = tmp_dir.join(format!("{package_id}-{version}"));
        tokio::fs::create_dir_all(&extract_dir).await?;

        let tp = extract_dir.to_path_buf();
        let tar_path_clone = tar_path.clone();

        tokio::task::spawn_blocking(move || {
            let tar_gz = std::fs::File::open(&tar_path_clone)?;
            let decompressed = flate2::read::GzDecoder::new(tar_gz);
            let mut archive = tar::Archive::new(decompressed);
            archive.unpack(&tp)?;
            Ok::<(), AppError>(())
        })
        .await??;


        Ok(extract_dir)
    }


}




