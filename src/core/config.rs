use std::fs::{read_to_string, File};
use std::io::Write;
use std::path::PathBuf;

use anyhow::Result;

use serde_derive::{Deserialize, Serialize};

use dirs::home_dir;

use toml::from_str;

use crate::core::common::{IpOptions, ListenOptions, LoggingOptions, PingOptions};
use crate::core::konst::CONFIG_FILE;

#[derive(Deserialize, Debug, Serialize)]
pub struct Config {
    pub ping_options: PingOptions,
    pub ip_options: IpOptions,
    pub logging_options: LoggingOptions,
    pub listen_options: ListenOptions,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            ping_options: PingOptions::default(),
            ip_options: IpOptions::default(),
            logging_options: LoggingOptions::default(),
            listen_options: ListenOptions::default(),
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

        println!("Generating config file `{CONFIG_FILE}` in current directory.\n");
        let mut config_file = File::create(CONFIG_FILE)?;
        config_file.write_all(toml_config.as_bytes())?;
        println!("{toml_config}");

        Ok(())
    }
}
