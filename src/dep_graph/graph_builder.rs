use std::collections::HashMap;

use crate::{dep_graph::graph::DepGraph, deps_resolver::DepRef};

pub fn build_graph(
    resolved_deps: HashMap<String, Vec<DepRef>>,
    vulns: HashMap<String, Vec<String>>,
) -> DepGraph {
    let mut graph = DepGraph::new();

    for (package_id, deps) in resolved_deps {
        graph.add_node(&package_id);

        if let Some(pkg_vulns) = vulns.get(&package_id) {
            for vuln in pkg_vulns {
                graph.add_vulns(&package_id, vuln);
            }
        }

        for dep in deps {
            graph.add_edge(&package_id, &dep.name);
        }
    }

    graph
}
