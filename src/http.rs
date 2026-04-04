use serde::{Deserialize, Serialize};

use crate::error::AppError;

#[derive(Serialize, Deserialize, Debug)]
pub struct PypiResponse {
    pub info: PypiRequirements,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PypiRequirements {
    pub requires_dist: Vec<String>,
    pub requires_python: Option<String>,
}

pub async fn get_requires_dist(
    client: &reqwest::Client,
    package_id: &str,
    version: &str,
) -> Result<PypiRequirements, AppError> {
    let url = format!("https://pypi.org/pypi/{package_id}/{version}/json");
    let json: PypiResponse = client.get(url).send().await?.json().await?;
    Ok(json.info)
}


#[tokio::test]
async fn test_get_requires_dist() {
    let client = reqwest::Client::new();
    let requires_dist = get_requires_dist(&client, "twine", "4.0.2").await.unwrap();
    println!("{:?}", requires_dist)
}
