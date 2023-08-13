use tokio::time::{sleep, Duration};

pub async fn loop_handler(count: u16, repeat: u16, sleep_interval: u16) -> bool {
    if count == u16::MAX {
        println!("max ping count reached");
        return true;
    } else if repeat != 0 && count >= repeat {
        return true;
    } else {
        if count > 0 {
            sleep(Duration::from_millis(sleep_interval.into())).await;
        }
        return false;
    }
}
