use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{
        header::{COOKIE, SET_COOKIE},
        request, HeaderValue, StatusCode,
    },
    response::{IntoResponseParts, ResponseParts},
};
use cookie::Cookie;
use hyper::HeaderMap;
use serde_json::from_str;
use std::borrow::Cow;
use std::convert::Infallible;

pub struct SetCookie<'c>(pub Cookie<'c>);

impl<'c> IntoResponseParts for SetCookie<'c> {
    type Error = StatusCode;

    fn into_response_parts(self, mut res: ResponseParts) -> Result<ResponseParts, Self::Error> {
        let value = HeaderValue::from_str(self.0.encoded().to_string().as_str())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        res.headers_mut().append(SET_COOKIE, value);
        Ok(res)
    }
}

#[derive(Default)]
pub struct Cookies<'c>(Option<Vec<Cookie<'c>>>);

impl<'c> Cookies<'c> {
    pub fn get(&self, name: &str) -> Option<&'c Cookie> {
        match &self.0 {
            None => None,
            Some(cookies) => cookies.iter().find(|c| c.name() == name),
        }
    }

    pub fn from_str<S>(value: S) -> Self
    where
        S: Into<Cow<'c, str>>,
    {
        Self(Some(
            Cookie::split_parse(value)
                .filter_map(|c| c.ok())
                .collect::<Vec<Cookie>>(),
        ))
    }

    pub fn from_headers(headers: &HeaderMap) -> Self {
        headers
            .get(COOKIE)
            .and_then(|header| header.to_str().ok())
            .map_or(Self::default(), |value| Self::from_str(value.to_owned()))
    }
}

#[async_trait]
impl<'c, S> FromRequestParts<S> for Cookies<'c>
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self::from_headers(&parts.headers))
    }
}
