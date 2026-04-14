use clap::ValueEnum;

#[derive(Debug, Clone)]
pub enum Platform {
    AMD64,
    ARM64,
}

impl Platform {
    pub fn as_str(&self) -> &'static str {
        match self {
            Platform::AMD64 => "amd64",
            Platform::ARM64 => "arm64",
        }
    }
}

impl ValueEnum for Platform {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::AMD64, Self::ARM64]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(self.as_str().into())
    }
}
