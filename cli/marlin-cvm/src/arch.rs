use clap::ValueEnum;

#[derive(Debug, Clone)]
pub enum Arch {
    AMD64,
    ARM64,
}

impl Arch {
    pub fn as_str(&self) -> &'static str {
        match self {
            Arch::AMD64 => "amd64",
            Arch::ARM64 => "arm64",
        }
    }
}

impl ValueEnum for Arch {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::AMD64, Self::ARM64]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(self.as_str().into())
    }
}
