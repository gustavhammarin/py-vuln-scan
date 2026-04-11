use serde::{Deserialize, Serialize};

/// Toppnivå-svaret från `GET /pypi/{package}/{version}/json`.
#[derive(Serialize, Deserialize, Debug)]
pub struct PypiResponse {
    pub info: PypiRequirements,
}

/// Fälten vi bryr oss om under `info`-nyckeln.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PypiRequirements {
    pub requires_dist: Vec<String>,
    pub requires_python: Option<String>,
}
