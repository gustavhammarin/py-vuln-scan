use serde::{Deserialize, Serialize};

/// Top-level response from `GET /pypi/{package}/{version}/json`.
#[derive(Serialize, Deserialize, Debug)]
pub struct PypiResponse {
    pub info: PypiRequirements,
}

/// The fields we care about under the `info` key.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PypiRequirements {
    pub requires_dist: Vec<String>,
    pub requires_python: Option<String>,
}
