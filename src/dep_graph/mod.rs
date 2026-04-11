use std::collections::HashSet;

use serde::Serialize;

use crate::deps_resolver::{DepRef};
use crate::osv::OsvVuln;

/// Ett paket i det nestade dependency-trädet.
/// `depends_on` innehåller paketets direkta beroenden rekursivt.
#[derive(Serialize, Clone)]
pub struct PackageRef {
    pub name: String,
    pub version: String,
    pub depends_on: Vec<Box<PackageRef>>,
    pub vuln_ids: Vec<String>,
}

impl PackageRef {
    pub fn build_vuln_chains(&self) -> Vec<VulnChain> {
        let mut path = Vec::new();
        let mut chains = Vec::new();

        self.collect_chains(&mut path, &mut chains);
        chains
    }
    pub fn collect_chains(&self, path: &mut Vec<DepRef>, chains: &mut Vec<VulnChain>) {
        path.push(DepRef {
            name: self.name.clone(),
            version: self.version.clone(),
        });

        for _dep in &self.depends_on {
            let dep = _dep.as_ref();
            if !dep.vuln_ids.is_empty() {
                let mut chain = path.clone();
                chain.push(DepRef {
                    name: dep.name.clone(),
                    version: dep.version.clone(),
                });
                chains.push(VulnChain { chain });
            }
            dep.collect_chains(path, chains);
        }

        path.pop();
    }
}

/// Bygg ett nestat PackageRef-träd från en flat adjacency-lista.
///
/// `visited` håller koll på redan besökta noder för att undvika
/// oändliga loopar vid cirkulära beroenden.
pub fn build_tree(
    root: &str,
    root_ver: &str,
    graph: &std::collections::HashMap<String, Vec<DepRef>>,
    vulns: &[OsvVuln],
    visited: &mut HashSet<String>,
) -> PackageRef {
    let key = format!("{}@{}", root, root_ver);

    let vuln_ids: Vec<String> = vulns
        .iter()
        .filter(|v| {
            v.affected.iter().flatten().any(|a| {
                a.package
                    .as_ref()
                    .is_some_and(|p| p.name.eq_ignore_ascii_case(root))
            })
        })
        .map(|v| v.id.clone())
        .collect();

    // Om noden redan är besökt returnerar vi den utan barn — bryter cykeln.
    if !visited.insert(key) {
        return PackageRef {
            name: root.to_string(),
            version: root_ver.to_string(),
            depends_on: vec![],
            vuln_ids,
        };
    }

    let deps = graph.get(root).cloned().unwrap_or_default();

    PackageRef {
        name: root.to_string(),
        version: root_ver.to_string(),
        depends_on: deps
            .iter()
            .map(|dep| Box::new(build_tree(&dep.name, &dep.version, graph, vulns, visited)))
            .collect(),
        vuln_ids,
    }
}

#[derive(Debug, Serialize)]
pub struct VulnChain {
    pub chain: Vec<DepRef>,
}
