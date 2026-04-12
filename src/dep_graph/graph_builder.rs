use std::collections::HashMap;

use crate::{dep_graph::graph::DepGraph, deps_resolver::PkgRef};

pub fn build_graph(
    resolved_deps: HashMap<PkgRef, Vec<PkgRef>>,
    vulns: HashMap<String, Vec<String>>,
) -> DepGraph {
    let mut graph = DepGraph::new();

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
