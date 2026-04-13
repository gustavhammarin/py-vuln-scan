use rayon::prelude::*;
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use crate::{dep_graph::graph::DepNode, error::AppError};

pub struct CodeAnalyzer {
    parser: Arc<Mutex<tree_sitter::Parser>>,
    pub dep_to_track: DepNode,
    pub target_dep: DepNode,
    pub source_files: Vec<PathBuf>,
}

impl CodeAnalyzer {
    pub fn new(dep_to_track: &DepNode, target_dep: &DepNode, source_dir: &Path) -> Result<Self, AppError> {
        println!("source_dir: {:?}", source_dir);
        let source_files = Self::collect_files(source_dir)?;
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&tree_sitter_python::LANGUAGE.into())?;

        Ok(Self {
            parser: Arc::new(Mutex::new(parser)),
            dep_to_track: dep_to_track.clone(),
            target_dep: target_dep.clone(),
            source_files,
        })
    }

    fn collect_files(dir: &Path) -> Result<Vec<PathBuf>, AppError> {
        let mut files = Vec::new();
        for entry in walkdir::WalkDir::new(&dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .filter(|e| e.path().extension().map_or(false, |ext| ext == "py"))
            {
                files.push(entry.path().to_path_buf());
            }

        Ok(files)
    }

    pub fn analyze(&self) -> Result<Vec<String>, AppError> {
        let results: Vec<String> = self
            .source_files
            .par_iter()
            .map(|file| self.analyze_file(file))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .into();

        Ok(results)
    }

    fn analyze_file(&self, file: &Path) -> Result<Option<String>, AppError> {
        println!("analyzing path: {:?}", file);
        let content = std::fs::read_to_string(file)?;
        let mut parser = self.parser.lock().unwrap();
        let tree = parser
            .parse(&content, None)
            .ok_or(AppError::TreeSitterTreeParsingError(
                "failed to parse file".to_string(),
            ))?;

        let result = self.find_imports(tree.root_node(), &content)?;

        match result {
            Some(t) => Ok(Some(t.join(" | "))),
            None => Ok(None),
        }
    }

    fn find_imports(
        &self,
        root: tree_sitter::Node,
        content: &str,
    ) -> Result<Option<Vec<String>>, AppError> {
        let mut imports = self.traverse_for_imports(root, content);

        if imports.is_empty() {
            return Ok(None);
        }

        let calls = self.traverse_for_calls(root, content);

        imports.extend(calls);

        Ok(Some(imports))
    }

    fn traverse_for_imports(&self, root: tree_sitter::Node, content: &str) -> Vec<String> {
        let mut results = Vec::new();
        let mut queue = vec![root];

        while let Some(node) = queue.pop() {
            if node.kind() == "import_statement" || node.kind() == "import_from_statement" {
                if let Ok(text) = node.utf8_text(content.as_bytes()) {
                    if text.contains(&self.dep_to_track.package_id) {
                        results.push(text.trim().to_string());
                    }
                }
            }

            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                queue.push(child);
            }
        }

        results
    }

    fn traverse_for_calls(&self, root: tree_sitter::Node, content: &str) -> Vec<String> {
        let mut results = Vec::new();
        let mut queue = vec![root];

        while let Some(node) = queue.pop() {
            if node.kind() == "call" {
                if let Some(func_node) = node.child(0) {
                    if let Ok(text) = func_node.utf8_text(content.as_bytes()) {
                        results.push(text.trim().to_string());
                    }
                }
            }

            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                queue.push(child);
            }
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use crate::dep_graph::graph::DepNode;
    use crate::reachability_analysis::code_analyser::analyzer::CodeAnalyzer;
    use std::collections::HashSet;
    use std::fs;
    use std::io::Write;

    #[test]
    fn test_analyze_finds_vulnerable_imports() -> Result<(), Box<dyn std::error::Error>> {
        // Create temp directory for test
        let temp_dir = tempfile::tempdir()?;
        let temp_path = temp_dir.path();

        // Create test Python-file with requests import and calls
        let test_file = temp_path.join("test.py");
        let mut file = fs::File::create(&test_file)?;
        writeln!(
            file,
            r#"
import requests
from requests import get

def fetch_data(url):
    response = requests.get(url)
    return response.json()

def another_func():
    data = get("https://example.com")
    return data
"#
        )?;

        // Create DepNodes
               let dep_to_track = DepNode {
            package_id: "requests".to_string(),
            version: "2.25.0".to_string(),
            vulnerabilities: HashSet::from(["fdsafs".to_string(), "fdsafdsa".to_string()]),
            is_vulnerable: true,
        };

          let target_dep = DepNode {
            package_id: "my_app".to_string(),
            version: "1.0.0".to_string(),
            vulnerabilities: HashSet::from([]),
            is_vulnerable: false,
        };

        // Create analyzer
        let analyzer = CodeAnalyzer::new(&dep_to_track, &target_dep, temp_path)?;

        // Analyze
        let results = analyzer.analyze()?;

        // Assertions
        assert!(!results.is_empty(), "Should find imports");

        let joined = results.join(" | ");
        assert!(
            joined.contains("import requests"),
            "Should find import requests"
        );
        assert!(
            joined.contains("from requests import get"),
            "Should find from import"
        );
        assert!(
            joined.contains("requests.get"),
            "Should find function calls"
        );

        Ok(())
    }

    #[test]
    fn test_analyze_returns_none_when_no_vulnerable_imports()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempfile::tempdir()?;
        let temp_path = temp_dir.path();

        let test_file = temp_path.join("test.py");
        let mut file = fs::File::create(&test_file)?;
        writeln!(
            file,
            r#"
import os
import sys

def some_func():
    return os.getcwd()
"#
        )?;

        let dep_to_track = DepNode {
            package_id: "requests".to_string(),
            version: "2.25.0".to_string(),
            vulnerabilities: HashSet::from(["fdsafs".to_string(), "fdsafdsa".to_string()]),
            is_vulnerable: true,
        };

        let target_dep = DepNode {
            package_id: "my_app".to_string(),
            version: "1.0.0".to_string(),
            vulnerabilities: HashSet::from([]),
            is_vulnerable: false,
        };

        let analyzer = CodeAnalyzer::new(&dep_to_track, &target_dep, temp_path)?;
        let results = analyzer.analyze()?;

        assert!(
            results.is_empty(),
            "Should return empty vec when no vulnerable imports"
        );

        Ok(())
    }

    #[test]
    fn test_analyze_with_nested_imports() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempfile::tempdir()?;
        let temp_path = temp_dir.path();

        // Skapa en fil med nested calls
        let test_file = temp_path.join("test.py");
        let mut file = fs::File::create(&test_file)?;
        writeln!(
            file,
            r#"
from requests.auth import HTTPBasicAuth
import requests

def authenticate():
    auth = HTTPBasicAuth("user", "pass")
    response = requests.get("https://api.example.com", auth=auth)
    return response
"#
        )?;

        let dep_to_track = DepNode {
            package_id: "requests".to_string(),
            version: "2.25.0".to_string(),
            vulnerabilities: HashSet::from(["fdsafs".to_string(), "fdsafdsa".to_string()]),
            is_vulnerable: true,
        };

        let target_dep = DepNode {
            package_id: "my_app".to_string(),
            version: "1.0.0".to_string(),
            vulnerabilities: HashSet::from([]),
            is_vulnerable: false,
        };

        let analyzer = CodeAnalyzer::new(&dep_to_track, &target_dep, temp_path)?;
        let results = analyzer.analyze()?;

        assert!(!results.is_empty());
        let joined = results.join(" | ");
        assert!(joined.contains("requests"));

        Ok(())
    }
}
