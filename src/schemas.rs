use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct OsvQuery{
    pub package: OsvPackage,
    pub version: String
}
#[derive(Serialize)]
pub struct OsvPackage{
    pub name: String,
    pub ecosystem: String
}

#[derive(Deserialize, Debug)]
pub struct OsvResponse {
    pub vulns: Option<Vec<OsvVuln>>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct OsvVuln {
    pub schema_version: Option<String>,
    pub id: String,
    pub modified: Option<String>,
    pub published: Option<String>,
    pub withdrawn: Option<String>,
    pub aliases: Option<Vec<String>>,
    pub upstream: Option<Vec<String>>,
    pub related: Option<Vec<String>>,
    pub summary: Option<String>,
    pub details: Option<String>,
    pub severity: Option<Vec<OsvSeverity>>,
    pub affected: Option<Vec<OsvAffected>>,
    pub references: Option<Vec<OsvReference>>,
    pub credits: Option<Vec<OsvCredit>>,
    pub database_specific: Option<serde_json::Value>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct OsvSeverity {
    pub r#type: String,
    pub score: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct OsvAffected {
    pub package: Option<OsvAffectedPackage>,
    pub severity: Option<Vec<OsvSeverity>>,
    pub ranges: Option<Vec<OsvRange>>,
    pub versions: Option<Vec<String>>,
    pub ecosystem_specific: Option<serde_json::Value>,
    pub database_specific: Option<serde_json::Value>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct OsvAffectedPackage {
    pub ecosystem: String,
    pub name: String,
    pub purl: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct OsvRange {
    pub r#type: String,
    pub repo: Option<String>,
    pub events: Option<Vec<OsvEvent>>,
    pub database_specific: Option<serde_json::Value>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct OsvEvent {
    pub introduced: Option<String>,
    pub fixed: Option<String>,
    pub last_affected: Option<String>,
    pub limit: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct OsvReference {
    pub r#type: String,
    pub url: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct OsvCredit {
    pub name: String,
    pub contact: Option<Vec<String>>,
    pub r#type: Option<String>,
}