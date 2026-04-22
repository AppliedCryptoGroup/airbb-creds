use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("too many messages: got {got}, max is {max}")]
    TooManyMessages { got: usize, max: usize },
    #[error("message vector must not be empty")]
    EmptyMessages,
    #[error("signature is not a valid curve point")]
    InvalidSignature,
}
