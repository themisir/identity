use std::fmt::Formatter;

use serde::{de, Deserialize, Deserializer};

#[derive(Copy, Clone, Debug)]
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

impl<'de> Deserialize<'de> for Duration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DurationVisitor;

        impl<'de> de::Visitor<'de> for DurationVisitor {
            type Value = chrono::Duration;

            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                write!(formatter, "Duration")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v.is_empty() {
                    return Err(de::Error::custom("empty duration value"));
                }

                let mut total_seconds = 0i64;
                let mut i = 0;

                while let Some(ch) = v.chars().nth(i) {
                    if ch.is_numeric() {
                        let mut unit_value = 0u32;
                        let mut num = ch;
                        loop {
                            unit_value = unit_value * 10 + (num as u8 - b'0') as u32;

                            i += 1;
                            if let Some(next) = v.chars().nth(i) {
                                num = next;
                                if !next.is_numeric() {
                                    let coefficient = match next {
                                        's' => 1,
                                        'm' => 60,
                                        'h' => 60 * 60,
                                        'd' => 60 * 60 * 24,
                                        _ => {
                                            return Err(de::Error::custom(format!(
                                                "invalid unit: {}",
                                                next
                                            )));
                                        }
                                    };

                                    total_seconds += unit_value as i64 * coefficient;
                                    i += 1;

                                    break;
                                }
                            } else {
                                return Err(de::Error::custom("expected duration unit"));
                            }
                        }
                    } else {
                        return Err(de::Error::custom(format!(
                            "expected duration value but reached {}",
                            ch
                        )));
                    }
                }

                Ok(chrono::Duration::seconds(total_seconds))
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_str(&v)
            }
        }

        let value = deserializer.deserialize_str(DurationVisitor)?;
        Ok(Duration(value))
    }
}
