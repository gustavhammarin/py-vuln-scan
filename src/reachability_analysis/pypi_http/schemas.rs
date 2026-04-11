use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct PypiResponse {
    pub urls: Vec<UrlInfo>,
}

impl PypiResponse {
    pub fn get_sdist(&self) -> Option<String> {
        self.urls
            .iter()
            .find(|u| u.packagetype == "sdist")
            .map(|u| u.url.clone())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UrlInfo {
    pub packagetype: String,
    pub url: String,
}