#[derive(Copy, Clone)]
pub struct Duration(chrono::Duration);

impl From<chrono::Duration> for Duration {
    fn from(value: chrono::Duration) -> Self {
        Self(value)
    }
}

impl From<cookie::time::Duration> for Duration {
    fn from(value: cookie::time::Duration) -> Self {
        Self(chrono::Duration::milliseconds(
            value.whole_milliseconds() as i64
        ))
    }
}

impl From<Duration> for chrono::Duration {
    fn from(value: Duration) -> Self {
        value.0
    }
}

impl From<Duration> for cookie::time::Duration {
    fn from(value: Duration) -> Self {
        cookie::time::Duration::milliseconds(value.0.num_milliseconds())
    }
}
