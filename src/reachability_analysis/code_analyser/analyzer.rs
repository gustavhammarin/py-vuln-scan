use rayon::prelude::*;
use serde::Serialize;
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

#[derive(Serialize, Debug, Clone)]
pub struct Finding{
    pub package_id: String,
    pub version: String,
    pub file_path: String,
    pub extracted_content: String
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

    pub fn analyze(&self) -> Result<Vec<Finding>, AppError> {
        let results: Vec<Finding> = self
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

    fn analyze_file(&self, file: &Path) -> Result<Option<Finding>, AppError> {
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
            Some(t) => Ok(Some(Finding{
                package_id: self.target_dep.package_id.clone(),
                version: self.target_dep.version.clone(),
                file_path: file.to_string_lossy().to_string(),
                extracted_content: t.join(" | "),
            })),
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
