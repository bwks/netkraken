use std::fs::{File, read_to_string};
use std::io::Write;
use std::path::PathBuf;

use anyhow::Result;

use serde_derive::{Deserialize, Serialize};

use toml::from_str;

use crate::core::common::{IpOptions, ListenOptions, LoggingOptions, PingOptions};

/// Configuration options for NetKraken
#[derive(Deserialize, Debug, Default, Serialize)]
pub struct Config {
    pub ping_options: PingOptions,
    pub ip_options: IpOptions,
    pub logging_options: LoggingOptions,
    pub listen_options: ListenOptions,
}

impl Config {
    /// Load a config file from the current directory.
    pub fn load(filename: &str) -> Result<Config> {
        let mut config_file_path = PathBuf::from(".");
        config_file_path.push(filename);

        let config = read_to_string(config_file_path)?;
        let config: Config = from_str(&config)?;

        Ok(config)
    }

    /// Generate a default config file
    pub fn generate(file: &str, force: bool) -> Result<()> {
        let create = match PathBuf::from(file).exists() {
            true => {
                println!("Config file `{file}` already exists in current directory.\n");
                force
            }
            false => true,
        };
        if create {
            let config = Config::default();
            let toml_config = toml::to_string(&config)?;

            println!("Generating default config file `{file}` in current directory.\n");
            let mut config_file = File::create(file)?;
            config_file.write_all(toml_config.as_bytes())?;
            println!("{toml_config}");
        }

        Ok(())
    }
}
