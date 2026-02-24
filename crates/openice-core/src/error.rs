use thiserror::Error;

#[derive(Error, Debug)]
pub enum OpenIceError {
    #[error("Process operation failed: {0}")]
    ProcessError(String),

    #[error("Network enforcement failed: {0}")]
    NetworkError(String),

    #[error("Persistence operation failed: {0}")]
    PersistenceError(String),

    #[error("Policy error: {0}")]
    PolicyError(String),

    #[error("Identifier matching error: {0}")]
    IdentifierError(String),

    #[error("Resource governance error: {0}")]
    ResourceError(String),

    #[error("Rollback failed: {0}")]
    RollbackError(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Windows API error: {code:#X} - {message}")]
    WindowsApi { code: u32, message: String },

    #[error("Not implemented: {0}")]
    NotImplemented(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),
}
