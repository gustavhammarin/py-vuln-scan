use std::collections::{HashMap, HashSet};

use serde::Serialize;
use serde_json::{Value, json};

use crate::deps_resolver::PkgRef;

#[derive(Serialize, Debug, Clone, Default)]
pub struct DepNode {
    pub package_id: String,
    pub version: String,
    pub vulnerabilities: HashSet<String>,
    pub is_vulnerable: bool,
}

pub struct DepGraph {
    nodes: HashMap<String, DepNode>,
    edges: HashMap<String, Vec<String>>,
    reverse_edges: HashMap<String, Vec<String>>,
}

impl DepGraph {
    fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: HashMap::new(),
            reverse_edges: HashMap::new(),
        }
    }

    pub fn build_graph(
        resolved_deps: HashMap<PkgRef, Vec<PkgRef>>,
        vulns: HashMap<String, Vec<String>>,
    ) -> Self {
        let mut graph = Self::new();

        for (pkg, deps) in resolved_deps.iter() {
            graph.add_node(&pkg.name, &pkg.version);

            if let Some(pkg_vulns) = vulns.get(&pkg.name) {
                for vuln in pkg_vulns {
                    graph.add_vulns(&pkg.name, vuln);
                }
            }

            for dep in deps {
                graph.add_edge(&pkg.name, &dep.name);
            }
        }

        graph
    }

    fn add_node(&mut self, package_id: &str, version: &str) {
        self.nodes.insert(
            package_id.to_string(),
            DepNode {
                package_id: package_id.to_string(),
                version: version.to_string(),
                vulnerabilities: HashSet::new(),
                is_vulnerable: false,
            },
        );
        self.edges
            .entry(package_id.to_string())
            .or_insert_with(Vec::new);
        self.reverse_edges
            .entry(package_id.to_string())
            .or_insert_with(Vec::new);
    }

    fn add_edge(&mut self, from: &str, to: &str) {
        self.edges
            .entry(from.to_string())
            .or_insert_with(Vec::new)
            .push(to.to_string());

        self.reverse_edges
            .entry(to.to_string())
            .or_insert_with(Vec::new)
            .push(from.to_string());
    }

    fn add_vulns(&mut self, package_id: &str, vuln_id: &str) {
        if let Some(node) = self.nodes.get_mut(package_id) {
            node.is_vulnerable = true;
            node.vulnerabilities.insert(vuln_id.to_string());
        }
    }

    pub fn find_all_vulnerable_chains(&self, root: &str) -> Vec<Vec<DepNode>> {
        let mut all_chains: Vec<Vec<DepNode>> = Vec::new();

        for (_, node) in &self.nodes {
            if node.is_vulnerable {
                let result = self.find_all_paths_to_root(&node.package_id, root);
                all_chains.extend(result);
            }
        }
        all_chains
    }

    fn find_all_paths_to_root(&self, from: &str, root: &str) -> Vec<Vec<DepNode>> {
        let from_node = self.nodes.get(from).cloned().unwrap_or_default();

        let mut paths = Vec::new();
        let mut current_path = vec![from_node];
        self.find_paths_up(from, root, &mut current_path, &mut paths);
        paths
    }

    fn find_paths_up(
        &self,
        current: &str,
        target: &str,
        path: &mut Vec<DepNode>,
        all_paths: &mut Vec<Vec<DepNode>>,
    ) {
        if current == target {
            all_paths.push(path.clone());
            return;
        }

        if let Some(parents) = self.reverse_edges.get(current) {
            for parent in parents {
                if !path.iter().any(|p| p.package_id == *parent) {
                    if let Some(parent_node) = self.nodes.get(parent.as_str()) {
                        path.push(parent_node.clone());
                        self.find_paths_up(parent, target, path, all_paths);
                        path.pop();
                    }
                }
            }
        }
    }

    pub fn to_json(&self) -> Result<String, serde_json::error::Error> {
        let nodes: Vec<&DepNode> = self.nodes.values().collect();

        let edges: Vec<Value> = self
            .edges
            .iter()
            .flat_map(|(from, to_list)| {
                to_list.iter().map(move |to| {
                    json!({
                        "from": from,
                        "to": to
                    })
                })
            })
            .collect();

        let vulnerabilities: Vec<Value> = self
            .nodes
            .iter()
            .filter_map(|(pkg_id, node)| {
                if node.is_vulnerable {
                    Some(json!({
                        "package": pkg_id,
                        "vulns": node.vulnerabilities.iter().collect::<Vec<_>>()
                    }))
                } else {
                    None
                }
            })
            .collect();

        let json = json!({
            "nodes": nodes,
            "edges": edges,
            "vulnerabilities": vulnerabilities,
            "summary": {
                "total_packages": self.nodes.len(),
                "vulnerable_packages": self.nodes.values().filter(|n| n.is_vulnerable).count(),
                "total_edges": self.edges.values().map(|v| v.len()).sum::<usize>()
            }
        });

        serde_json::to_string_pretty(&json)
    }
}
