#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid version: {0}")]
    InvalidVersion(String),

    #[error("resolution failed: {0}")]
    Resolution(String),

    #[error("task join failed: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("Tree sitter error: {0}")]
    TreeSitterLanguageError(#[from] tree_sitter::LanguageError),
    #[error("Tree sitter error: {0}")]
    TreeSitterTreeParsingError(String),
}
