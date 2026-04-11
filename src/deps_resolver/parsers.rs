use std::str::FromStr;

use pep508_rs::{
    ExtraName, MarkerEnvironment, MarkerEnvironmentBuilder, Requirement, VerbatimUrl,
    pep440_rs::VersionSpecifiers,
};

use super::pypi::schemas::PypiRequirements;

/// Build a hardcoded Linux/CPython 3.11 environment for marker evaluation.
/// This is used to filter out platform- and version-specific dependencies.
fn linux_marker_env() -> MarkerEnvironment {
    MarkerEnvironmentBuilder {
        implementation_name: "cpython",
        implementation_version: "3.11.0",
        os_name: "posix",
        platform_machine: "x86_64",
        platform_python_implementation: "CPython",
        platform_release: "",
        platform_system: "Linux",
        platform_version: "",
        python_full_version: "3.11.0",
        python_version: "3.11",
        sys_platform: "linux",
    }
    .try_into()
    .expect("static marker env is valid")
}

/// Parse `requires_dist` strings into structured `Requirement` objects.
/// Filters out packages that are incompatible with Python 3.11 / Linux.
pub fn parse_deps(reqs: PypiRequirements) -> Vec<Requirement<VerbatimUrl>> {
    // Skip the package entirely if it requires a Python version other than 3.11.
    if let Some(spec_str) = reqs.requires_python.filter(|s| !s.is_empty()) {
        if let Ok(specifiers) = VersionSpecifiers::from_str(&spec_str) {
            let py311 = pep508_rs::pep440_rs::Version::from_str("3.11.0").unwrap();
            if !specifiers.contains(&py311) {
                return vec![];
            }
        }
    }

    let env = linux_marker_env();

    reqs.requires_dist
        .into_iter()
        .filter_map(|s| Requirement::from_str(&s).ok())
        .filter(|req| req.evaluate_markers(&env, &[] as &[ExtraName]))
        .collect()
}

#[tokio::test]
async fn test_parse_deps() {
    let client = reqwest::Client::new();
    let requirements = super::pypi::client::get_requires_dist(&client, "twine", "4.0.2")
        .await
        .unwrap();
    let parsed = parse_deps(requirements);
    println!("{:?}", parsed);
}
