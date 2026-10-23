use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

pub const CONFIG_PATH: &str = "/etc/loginctl.conf";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub pam_file: PathBuf,
}

impl Config {
    pub fn load() -> Result<Self> {
        Self::load_from(Path::new(CONFIG_PATH))
    }

    pub fn load_from(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("read configuration {}", path.display()))?;
        Self::parse(&contents).with_context(|| format!("parse configuration {}", path.display()))
    }

    pub fn parse(contents: &str) -> Result<Self> {
        let mut pam_file = None;
        for (index, raw) in contents.lines().enumerate() {
            let line_number = index + 1;
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                bail!("line {line_number}: expected key = \"value\"");
            };
            let key = key.trim();
            let value = parse_quoted(value.trim())
                .with_context(|| format!("line {line_number}: invalid value for {key}"))?;
            match key {
                "pam_file" => {
                    if pam_file.is_some() {
                        bail!("line {line_number}: duplicate pam_file setting");
                    }
                    let path = PathBuf::from(value);
                    if !path.is_absolute() {
                        bail!("line {line_number}: pam_file must be absolute");
                    }
                    pam_file = Some(path);
                }
                _ => bail!("line {line_number}: unknown setting {key}"),
            }
        }
        Ok(Self {
            pam_file: pam_file.context("missing required pam_file setting")?,
        })
    }
}

fn parse_quoted(raw: &str) -> Result<String> {
    if raw.len() < 2 || !raw.starts_with('"') || !raw.ends_with('"') {
        bail!("value must be double-quoted");
    }
    let mut output = String::new();
    let mut escaped = false;
    for character in raw[1..raw.len() - 1].chars() {
        if escaped {
            match character {
                '\\' | '"' => output.push(character),
                _ => bail!(r#"only \\ and \" escapes are supported"#),
            }
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character.is_control() {
            bail!("control characters are not allowed");
        } else {
            output.push(character);
        }
    }
    if escaped {
        bail!("unterminated escape");
    }
    if output.is_empty() {
        bail!("value must not be empty");
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_single_strict_setting() {
        assert_eq!(
            Config::parse("# loginctl\npam_file = \"/etc/pam.d/system-login\"\n")
                .expect("valid config"),
            Config {
                pam_file: "/etc/pam.d/system-login".into()
            }
        );
    }

    #[test]
    fn rejects_missing_duplicate_unknown_relative_and_unquoted_values() {
        for contents in [
            "",
            "pam_file = \"/one\"\npam_file = \"/two\"\n",
            "other = \"/etc/pam.d/x\"\n",
            "pam_file = \"relative\"\n",
            "pam_file = /etc/pam.d/x\n",
            "pam_file = \"/etc/pam.d/x\" # comment\n",
        ] {
            assert!(Config::parse(contents).is_err(), "accepted {contents:?}");
        }
    }
}
