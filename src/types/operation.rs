
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Operation {
    Encrypt,
    Decrypt,
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encrypt => write!(f, "encrypt"),
            Self::Decrypt => write!(f, "decrypt"),
        }
    }
}