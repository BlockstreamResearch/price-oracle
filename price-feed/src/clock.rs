use std::time::{SystemTime, UNIX_EPOCH};

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since_epoch| since_epoch.as_secs())
        .unwrap_or_default()
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Clock {
    #[default]
    System,
    Fixed(u64),
}

impl Clock {
    pub fn now(&self) -> u64 {
        match self {
            Self::System => unix_now(),
            Self::Fixed(seconds) => *seconds,
        }
    }
}
