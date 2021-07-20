use alloc::string::String;

pub type Result<T> = core::result::Result<T, Error>;

/// Error types
#[derive(Debug)]
pub enum Error {
    ParametersNotSet,
    InvalidPublicKey,
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::ParametersNotSet => write!(f, "dsa: parameters not set up before generating key"),
            Error::InvalidPublicKey => write!(f, "dsa: invalid public key"),
        }
    }
}