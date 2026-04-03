use std::error::Error;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct PypiResponse{
    pub info: PypiRequirements
}
#[derive(Serialize, Deserialize, Debug)]
pub struct PypiRequirements{
    pub requires_dist: Vec<String>,
    pub requires_python: Option<String>
}

pub async fn get_requires_dist(
    client: &reqwest::Client,
    package_id: &str,
    version: &str,
) -> Result<PypiRequirements, Box<dyn Error>> {

    let url = format!("https://pypi.org/pypi/{package_id}/{version}/json");
    let response = client
        .get(url)
        .send()
        .await?;

    let json: PypiResponse = response.json().await?;

    Ok(json.info)
}




#[tokio::test]
async fn test_get_requires_dist(){
    let client = reqwest::Client::new();

    let requires_dist = get_requires_dist(&client, "twine", "4.0.2").await.unwrap();

    println!("{:?}", requires_dist)
}