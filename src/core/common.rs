#[derive(Debug)]
pub struct PingOptions {
    pub repeat: u8,
    pub interval: u16,
}

impl Default for PingOptions {
    fn default() -> Self {
        Self {
            repeat: 4,
            interval: 1000,
        }
    }
}
