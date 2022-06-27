use thiserror::Error;

#[derive(Error, Debug)]
pub enum TFTPError {
    #[error("Failed to convert input to NetASCII: {0}")]
    NetASCIIError(#[source] anyhow::Error),

    #[error("Mode is unsupported: {0}")]
    UnsupportedMode(String),

    #[error("MalformedPacket: {0}")]
    MalformedPacket(String),

    #[error("General error: {0}")]
    GeneralError(#[source] anyhow::Error),

    #[error("I/O error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("Operation timed out: {0}")]
    TimeoutError(String),
}
