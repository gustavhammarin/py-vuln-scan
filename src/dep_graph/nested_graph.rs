// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

use std::collections::{HashMap, HashSet};

use serde::Serialize;

use crate::{deps_resolver::PkgRef, osv::OsvVuln};

/// A node in the dependency tree.
/// Each node owns its children, making the tree recursive.
///
/// `Vec<DepNode>` — not `Vec<Box<DepNode>>`. Vec already heap-allocates
/// its buffer, so an extra Box layer only adds unnecessary indirection.
#[derive(Serialize, Clone)]
pub struct DepNode {
    pub name: String,
    pub version: String,
    pub depends_on: Vec<DepNode>,
    pub vuln_ids: Vec<String>,
}

impl DepNode {
    /// Build a dependency tree from `root`. Cycle detection is handled
    /// internally — callers do not need to pass a `visited` set.
    pub fn build(
        root: &str,
        root_ver: &str,
        graph: &HashMap<String, Vec<PkgRef>>,
        vulns: &[OsvVuln],
    ) -> Self {
        build_recursive(root, root_ver, graph, vulns, &mut HashSet::new())
    }

    pub fn is_vulnerable(&self) -> bool {
        !self.vuln_ids.is_empty()
    }

    /// Return all paths in the tree that terminate at a vulnerable package.
    pub fn vuln_chains(&self) -> Vec<VulnChain> {
        let mut chains = Vec::new();
        collect_chains(self, &mut Vec::new(), &mut chains);
        chains
    }
}

// ---------------------------------------------------------------------------
// Internal recursion
// ---------------------------------------------------------------------------

/// Recursive build — private so that `visited` does not leak to callers.
fn build_recursive(
    root: &str,
    root_ver: &str,
    graph: &HashMap<String, Vec<PkgRef>>,
    vulns: &[OsvVuln],
    visited: &mut HashSet<String>,
) -> DepNode {
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

    // Node already visited — return without children to break the cycle.
    if !visited.insert(key) {
        return DepNode {
            name: root.to_string(),
            version: root_ver.to_string(),
            depends_on: vec![],
            vuln_ids,
        };
    }

    let deps = graph.get(root).cloned().unwrap_or_default();

    DepNode {
        name: root.to_string(),
        version: root_ver.to_string(),
        depends_on: deps
            .iter()
            .map(|dep| build_recursive(&dep.name, &dep.version, graph, vulns, visited))
            .collect(),
        vuln_ids,
    }
}

/// DFS that collects all paths from a node down to a vulnerable package.
/// `path` is the current path from the root, built up and torn down recursively.
fn collect_chains(node: &DepNode, path: &mut Vec<ChainEntry>, chains: &mut Vec<VulnChain>) {
    path.push(ChainEntry {
        name: node.name.clone(),
        version: node.version.clone(),
        is_vulnerable: node.is_vulnerable(),
    });

    for dep in &node.depends_on {
        if dep.is_vulnerable() {
            // Directly vulnerable dependency — record the path including dep as the last node.
            let mut chain = path.clone();
            chain.push(ChainEntry {
                name: dep.name.clone(),
                version: dep.version.clone(),
                is_vulnerable: true,
            });
            chains.push(VulnChain { chain });
        }
        // Always recurse deeper — dep may have its own vulnerable dependencies.
        collect_chains(dep, path, chains);
    }

    path.pop();
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct VulnChain {
    pub chain: Vec<ChainEntry>,
}

/// One package in a vulnerability chain, from root down to the vulnerable node.
#[derive(Debug, Serialize, Clone)]
pub struct ChainEntry {
    pub name: String,
    pub version: String,
    pub is_vulnerable: bool,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::{deps_resolver::PkgRef, osv::{OsvAffected, OsvAffectedPackage, OsvVuln}};

    // --- Helpers ------------------------------------------------------------

    /// Build an adjacency list from triples of (parent, child, child_version).
    fn make_graph(edges: &[(&str, &str, &str)]) -> HashMap<String, Vec<PkgRef>> {
        let mut map: HashMap<String, Vec<PkgRef>> = HashMap::new();
        for &(parent, child, child_ver) in edges {
            map.entry(parent.to_string()).or_default().push(PkgRef {
                name: child.to_string(),
                version: child_ver.to_string(),
            });
        }
        map
    }

    /// Minimal OsvVuln that matches a single package name.
    fn make_vuln(id: &str, pkg_name: &str) -> OsvVuln {
        OsvVuln {
            id: id.to_string(),
            schema_version: None,
            modified: None,
            published: None,
            withdrawn: None,
            aliases: None,
            upstream: None,
            related: None,
            summary: None,
            details: None,
            severity: None,
            affected: Some(vec![OsvAffected {
                package: Some(OsvAffectedPackage {
                    ecosystem: "PyPI".to_string(),
                    name: pkg_name.to_string(),
                    purl: None,
                }),
                severity: None,
                ranges: None,
                versions: None,
                ecosystem_specific: None,
                database_specific: None,
            }]),
            references: None,
            credits: None,
            database_specific: None,
        }
    }

    // --- build tests --------------------------------------------------------

    #[test]
    fn leaf_no_deps_no_vulns() {
        let tree = DepNode::build("requests", "2.31.0", &HashMap::new(), &[]);
        assert_eq!(tree.name, "requests");
        assert_eq!(tree.version, "2.31.0");
        assert!(tree.depends_on.is_empty());
        assert!(!tree.is_vulnerable());
    }

    #[test]
    fn leaf_with_matching_vuln() {
        let vulns = vec![make_vuln("CVE-2023-001", "requests")];
        let tree = DepNode::build("requests", "2.31.0", &HashMap::new(), &vulns);
        assert!(tree.is_vulnerable());
        assert_eq!(tree.vuln_ids, ["CVE-2023-001"]);
    }

    #[test]
    fn vuln_matching_is_case_insensitive() {
        // OSV sometimes spells package names with mixed case e.g. "Requests"
        let vulns = vec![make_vuln("CVE-2023-001", "Requests")];
        let tree = DepNode::build("requests", "2.31.0", &HashMap::new(), &vulns);
        assert!(tree.is_vulnerable());
    }

    #[test]
    fn direct_dep_appears_as_child() {
        let graph = make_graph(&[("myapp", "requests", "2.31.0")]);
        let tree = DepNode::build("myapp", "1.0.0", &graph, &[]);
        assert_eq!(tree.depends_on.len(), 1);
        assert_eq!(tree.depends_on[0].name, "requests");
        assert_eq!(tree.depends_on[0].version, "2.31.0");
    }

    #[test]
    fn cycle_does_not_loop_forever() {
        // A → B → A — should return without hanging
        // Expected structure: a → b → a(stub, no children)
        let graph = make_graph(&[("a", "b", "1.0"), ("b", "a", "1.0")]);
        let tree = DepNode::build("a", "1.0", &graph, &[]);

        let b = &tree.depends_on[0];
        assert_eq!(b.name, "b");

        // The stub version of A inside B must have broken the cycle — no children.
        let a_stub = &b.depends_on[0];
        assert_eq!(a_stub.name, "a");
        assert!(a_stub.depends_on.is_empty());
    }

    // --- vuln_chains tests --------------------------------------------------

    #[test]
    fn no_vulns_gives_empty_chains() {
        let graph = make_graph(&[("myapp", "requests", "2.31.0")]);
        let tree = DepNode::build("myapp", "1.0.0", &graph, &[]);
        assert!(tree.vuln_chains().is_empty());
    }

    #[test]
    fn direct_vulnerable_dep_gives_two_node_chain() {
        // myapp → requests (vuln)
        let graph = make_graph(&[("myapp", "requests", "2.31.0")]);
        let vulns = vec![make_vuln("CVE-2023-001", "requests")];
        let tree = DepNode::build("myapp", "1.0.0", &graph, &vulns);

        let chains = tree.vuln_chains();
        assert_eq!(chains.len(), 1);

        let chain = &chains[0].chain;
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].name, "myapp");
        assert!(!chain[0].is_vulnerable);
        assert_eq!(chain[1].name, "requests");
        assert!(chain[1].is_vulnerable);
    }

    #[test]
    fn transitive_vulnerable_dep_gives_full_chain() {
        // myapp → a → requests (vuln)
        let graph = make_graph(&[("myapp", "a", "1.0"), ("a", "requests", "2.31.0")]);
        let vulns = vec![make_vuln("CVE-2023-001", "requests")];
        let tree = DepNode::build("myapp", "1.0.0", &graph, &vulns);

        let chains = tree.vuln_chains();
        assert_eq!(chains.len(), 1);

        let chain = &chains[0].chain;
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].name, "myapp");
        assert_eq!(chain[1].name, "a");
        assert_eq!(chain[2].name, "requests");
        assert!(chain[2].is_vulnerable);
    }

    #[test]
    fn two_vulnerable_deps_give_two_chains() {
        // myapp → a (vuln) and myapp → b (vuln)
        let graph = make_graph(&[("myapp", "a", "1.0"), ("myapp", "b", "1.0")]);
        let vulns = vec![make_vuln("CVE-001", "a"), make_vuln("CVE-002", "b")];
        let tree = DepNode::build("myapp", "1.0.0", &graph, &vulns);

        assert_eq!(tree.vuln_chains().len(), 2);
    }

    #[test]
    fn chain_through_two_vulnerable_nodes() {
        // myapp → a (vuln) → b (vuln)
        // Should produce two chains: [myapp, a] and [myapp, a, b]
        let graph = make_graph(&[("myapp", "a", "1.0"), ("a", "b", "1.0")]);
        let vulns = vec![make_vuln("CVE-001", "a"), make_vuln("CVE-002", "b")];
        let tree = DepNode::build("myapp", "1.0.0", &graph, &vulns);

        let chains = tree.vuln_chains();
        assert_eq!(chains.len(), 2);

        let lengths: Vec<usize> = chains.iter().map(|c| c.chain.len()).collect();
        assert!(lengths.contains(&2)); // [myapp, a]
        assert!(lengths.contains(&3)); // [myapp, a, b]
    }
}
