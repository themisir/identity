#[derive(Copy, Clone)]
pub struct Duration(pub chrono::Duration);

impl Duration {
    pub fn minutes(value: i64) -> Duration {
        chrono::Duration::minutes(value).into()
    }
}

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

impl Into<chrono::Duration> for Duration {
    fn into(self) -> chrono::Duration {
        self.0
    }
}

impl Into<cookie::time::Duration> for Duration {
    fn into(self) -> cookie::time::Duration {
        cookie::time::Duration::milliseconds(self.0.num_milliseconds())
    }
}
