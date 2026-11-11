use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

pub const CONFIG_PATH: &str = "/etc/loginctl.conf";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub pam_file: PathBuf,
    seat_setting: Option<String>,
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
        let mut seat_setting = None;
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
            let raw_value = value.trim();
            match key {
                "pam_file" => {
                    let value = parse_quoted(raw_value)
                        .with_context(|| format!("line {line_number}: invalid pam_file"))?;
                    if pam_file.is_some() {
                        bail!("line {line_number}: duplicate pam_file setting");
                    }
                    let path = PathBuf::from(value);
                    if !path.is_absolute() {
                        bail!("line {line_number}: pam_file must be absolute");
                    }
                    pam_file = Some(path);
                }
                "seats" => {
                    if seat_setting.is_some() {
                        bail!("line {line_number}: duplicate seats setting");
                    }
                    seat_setting = Some(raw_value.to_owned());
                }
                _ => bail!("line {line_number}: unknown setting {key}"),
            }
        }
        Ok(Self {
            pam_file: pam_file.context("missing required pam_file setting")?,
            seat_setting,
        })
    }
    /// Validate only for configured-seat listing/movement, never for PAM/scopes.
    pub fn configured_seats(&self) -> Result<Vec<String>> {
        let value = parse_quoted(
            self.seat_setting
                .as_deref()
                .context("missing explicit seats setting")?,
        )
        .context("invalid seats setting")?;
        let seats: Vec<String> = value.split_whitespace().map(str::to_owned).collect();
        if seats.is_empty() || seats.len() > 256 {
            bail!("configure between 1 and 256 explicit seats");
        }
        let mut unique = std::collections::BTreeSet::new();
        for seat in &seats {
            libmultiseatd::bus_name(seat)
                .map_err(|error| anyhow::anyhow!("invalid configured seat {seat}: {error}"))?;
            if !unique.insert(seat) {
                bail!("duplicate configured seat {seat}");
            }
        }
        Ok(seats)
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
                pam_file: "/etc/pam.d/system-login".into(),
                seat_setting: None
            }
        );
    }

    #[test]
    fn participants_are_explicit_unique_and_only_validated_when_needed() {
        for value in [
            None,
            Some("\"\""),
            Some("\"*\""),
            Some("\"seat0 seat0\""),
            Some("unquoted"),
            Some("\"bad/seat\""),
        ] {
            let input = format!(
                "pam_file = \"/etc/pam.d/x\"\n{}",
                value
                    .map(|value| format!("seats = {value}"))
                    .unwrap_or_default()
            );
            let config = Config::parse(&input).unwrap();
            assert_eq!(config.pam_file, PathBuf::from("/etc/pam.d/x"));
            assert!(config.configured_seats().is_err());
        }
        let config = Config::parse("pam_file = \"/etc/pam.d/x\"\nseats = \"seat0 seat1\"").unwrap();
        assert_eq!(config.configured_seats().unwrap(), ["seat0", "seat1"]);
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
