use std::fmt::{Display, Formatter, Write};

use hyper::Uri;
use serde::Serialize;
use url::form_urlencoded;

pub struct UriBuilder {
    origin: Option<String>,
    path: Option<String>,
    query: Option<String>,
}

impl Display for UriBuilder {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Some(origin) = &self.origin {
            write!(f, "{}", origin)?;
        }

        self.write_path_and_query(f)
    }
}

impl UriBuilder {
    pub fn new() -> Self {
        Self {
            origin: None,
            path: None,
            query: None,
        }
    }

    pub fn from_uri(uri: &Uri) -> Self {
        Self {
            origin: match (uri.scheme(), uri.authority()) {
                (Some(scheme), Some(authority)) => Some(format!("{}://{}", scheme, authority)),
                (None, Some(authority)) => Some(format!("://{}", authority)),
                (_, None) => None,
            },
            path: if uri.path().is_empty() {
                None
            } else {
                Some(uri.path().into())
            },
            query: uri.query().map(String::from),
        }
    }

    pub fn from_str(uri: &str) -> Result<Self, url::ParseError> {
        let uri = url::Url::parse(uri)?;

        Ok(Self {
            origin: {
                let origin = uri.origin();
                if origin.is_tuple() {
                    Some(origin.ascii_serialization())
                } else {
                    None
                }
            },
            path: Some(uri.path().into()),
            query: uri.query().map(String::from),
        })
    }

    pub fn set_origin<V>(mut self, origin: V) -> Self
    where
        V: AsRef<str>,
    {
        let s = origin.as_ref();
        self.origin = Some(s.trim_end_matches('/').into());
        self
    }

    pub fn set_path<V>(mut self, path: V) -> Self
    where
        V: Into<String>,
    {
        self.path = Some(path.into());
        self
    }

    pub fn append_path<V>(mut self, path: V) -> Self
    where
        V: AsRef<str>,
    {
        let path = path.as_ref();

        self.path = match self.path {
            None => Some(path.into()),
            Some(mut existing) => {
                if existing.ends_with('/') {
                    existing.write_str(path.trim_start_matches('/')).unwrap();
                    Some(existing)
                } else {
                    Some(format!("{}/{}", existing, path))
                }
            }
        };
        self
    }

    fn append_raw_params(&mut self, s: &str) {
        self.query = match &self.query {
            None => Some(String::from(s)),
            Some(params) => Some(if params.ends_with('&') {
                format!("{}{}", params, s)
            } else {
                format!("{}&{}", params, s)
            }),
        };
    }

    pub fn append_params<T>(mut self, params: T) -> Self
    where
        T: Serialize,
    {
        self.append_raw_params(serde_urlencoded::to_string(params).unwrap().as_str());
        self
    }

    pub fn append_param<V>(mut self, name: &str, value: V) -> Self
    where
        V: AsRef<str>,
    {
        let mut x = format!("{}=", name);

        form_urlencoded::byte_serialize(value.as_ref().as_bytes()).collect_into(&mut x);

        let s: String = form_urlencoded::byte_serialize(value.as_ref().as_bytes()).collect();
        self.append_raw_params(s.as_str());
        self
    }

    fn write_path_and_query<W>(&self, writer: &mut W) -> std::fmt::Result
    where
        W: Write,
    {
        if let Some(path) = &self.path {
            if path.starts_with('/') {
                writer.write_str(path.as_str())?;
            } else {
                write!(writer, "/{}", path.as_str())?;
            }
        }

        if let Some(params) = &self.query {
            write!(writer, "?{}", params.as_str())?;
        }

        Ok(())
    }
}
