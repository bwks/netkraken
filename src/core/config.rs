use serde_derive::Deserialize;

use crate::core::konst::{INTERVAL, REPEAT, TIMEOUT};

#[derive(Deserialize)]
pub struct Config {
    pub repeat: Option<u16>,
    pub interval: Option<u16>,
    pub timeout: Option<u16>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            repeat: Some(REPEAT),
            interval: Some(INTERVAL),
            timeout: Some(TIMEOUT),
        }
    }
}
