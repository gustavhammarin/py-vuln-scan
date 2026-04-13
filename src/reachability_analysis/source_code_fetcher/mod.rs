pub mod client;
mod schemas;

#[cfg(test)]
mod tests {
    use crate::reachability_analysis::source_code_fetcher::client::SourceCodeFetcher;

    use super::*;

    #[tokio::test]
    async fn test_get_source_code() {
        let temp = tempfile::TempDir::new().unwrap();
        let tmp_dir = temp.path();

        let pypi = SourceCodeFetcher::new();
        let source_path= pypi
            .get_source_code("twine", "4.0.2", tmp_dir)
            .await
            .unwrap();

        assert!(source_path.exists(), "source path should exist");
        assert!(source_path.is_dir(), "source path should be a directory");

        let py_files: Vec<_> = walkdir::WalkDir::new(&source_path)
            .into_iter()
            .flatten()
            .filter(|e| e.path().extension().and_then(|e| e.to_str()) == Some("py"))
            .collect();

        assert!(!py_files.is_empty(), "should contain .py files");
        drop(temp);
    }

    #[tokio::test]
    async fn test_concurrent() {
        let pypi = SourceCodeFetcher::new();
        let packages = vec![("twine", "4.0.2"), ("requests", "2.31.0")];

        let temp = tempfile::TempDir::new().unwrap();
        let tmp_dir = temp.path().to_path_buf();

        let handles: Vec<_> = packages
            .into_iter()
            .map(|(pkg, ver)| {
                let client = pypi.clone();
                let tp = tmp_dir.clone();
                tokio::spawn(async move { client.get_source_code(pkg, ver, &tp).await })
            })
            .collect();

        let results = futures::future::join_all(handles).await;

        drop(temp);
        for result in results {
            assert!(result.unwrap().is_ok());
        }
    }
}