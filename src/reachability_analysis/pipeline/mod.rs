/* use crate::{
    dep_graph::DepNode,
    error::AppError,
    reachability_analysis::pypi_http::client::PypiSourceClient,
};

pub async fn run_pipeline(packages: Vec<&DepNode>) -> Result<(), AppError> {
    let source_client = PypiSourceClient::new();

    for entry in packages {
        let (_temp, _source_path) = source_client
            .get_source_code(&entry.name, &entry.version)
            .await?;
    }
    todo!()
} */
