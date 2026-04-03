use std::{collections::HashSet, str::FromStr};

use pep508_rs::{
    Requirement, VerbatimUrl, marker,
    pep440_rs::{Version, VersionSpecifier, VersionSpecifiers},
};

use crate::http::{PypiRequirements, get_requires_dist};

pub fn parse_deps(
    reqs: PypiRequirements
) -> Vec<Requirement<VerbatimUrl>> {
    let all_versions: Vec<Version> = ["3.8.0", "3.9.0", "3.10.0", "3.11.0", "3.12.0"]
        .iter()
        .filter_map(|v| Version::from_str(v).ok())
        .collect();

    let python_versions = reqs.requires_python
        .filter(|s| !s.is_empty())  // behandla "" som None
        .and_then(|spec_str| VersionSpecifiers::from_str(spec_str.as_str()).ok())
        .map(|specifiers| {
            all_versions
                .iter()
                .filter(|v| specifiers.contains(v))
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or(all_versions);  // fallback till alla versioner

    reqs.requires_dist
        .into_iter()
        .filter_map(|s| Requirement::from_str(&s).ok())
        .filter(|req| {
            req.evaluate_extras_and_python_version(
                &HashSet::new(),
                &python_versions,
            )
        })
        .collect()
}

#[tokio::test]
async fn test_parse_deps() {
    let client = reqwest::Client::new();

    let requirements = get_requires_dist(&client, "twine", "4.0.2").await.unwrap();

    let parsed_result = parse_deps(requirements);

    println!("{:?}", parsed_result)
}
