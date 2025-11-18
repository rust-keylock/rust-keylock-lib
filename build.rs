use std::{env, error::Error, fmt, path::Path};

fn main() -> Result<(), RklBuildError> {
    let out_dir = env::var("OUT_DIR")?;
    generate_version(&out_dir)?;
    Ok(())
}

fn generate_version(out_dir: &str) -> Result<(), RklBuildError> {
    let dest_path = Path::new(&out_dir).join("rkl_version.rs");
    let version = env!("CARGO_PKG_VERSION");
    let contents = format!(
        "
pub(crate) fn rkl_version() -> &'static str {{
    \"{version}\"
}}
"
    );
    std::fs::write(dest_path, contents)?;
    Ok(())
}

#[derive(Debug)]
struct RklBuildError {
    description: String,
}

impl fmt::Display for RklBuildError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description)
    }
}

impl Error for RklBuildError {
    fn description(&self) -> &str {
        self.description.as_str()
    }
}

impl From<std::env::VarError> for RklBuildError {
    fn from(err: std::env::VarError) -> RklBuildError {
        RklBuildError {
            description: format!("{:?}", err),
        }
    }
}

impl From<std::io::Error> for RklBuildError {
    fn from(err: std::io::Error) -> RklBuildError {
        RklBuildError {
            description: format!("{:?}", err),
        }
    }
}
