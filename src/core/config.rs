use std::{fs::read_to_string, path::PathBuf};

use anyhow::Result;

use serde_derive::{Deserialize, Serialize};

use dirs::home_dir;

use toml::from_str;

use crate::core::common::PingOptions;

#[derive(Deserialize, Debug, Serialize)]
pub struct Config {
    pub ping_options: PingOptions,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            ping_options: PingOptions::default(),
        }
    }
}

impl Config {
    pub fn load(filename: &str) -> Result<Config> {
        let mut config_file = match home_dir() {
            Some(c) => c,
            None => PathBuf::from("."),
        };
        config_file.push(filename);

        let config = read_to_string(filename)?;
        let config: Config = from_str(&config)?;
        Ok(config)
    }
    pub fn generate() -> Result<()> {
        let config = Config::default();
        let toml_config = toml::to_string(&config)?;
        println!("{toml_config}");
        Ok(())
    }
}
