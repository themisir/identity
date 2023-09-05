use std::borrow::Cow;
use std::convert::Infallible;

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{
        header::{COOKIE, SET_COOKIE},
        request, HeaderMap, HeaderValue, StatusCode,
    },
    response::{IntoResponse, IntoResponseParts, Response, ResponseParts},
    Json,
};
use cookie::Cookie;
use log::error;
use serde::Serialize;

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

    pub fn extract_one<'a>(headers: &'a HeaderMap, name: &str) -> Option<Cookie<'a>> {
        headers
            .get(COOKIE)
            .and_then(|header| header.to_str().ok())
            .and_then(|value| {
                Cookie::split_parse(value)
                    .filter_map(|c| c.ok())
                    .find(|c| c.name() == name)
            })
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

pub struct AppError(anyhow::Error);

#[derive(Serialize)]
struct ErrorDto {
    message: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        error!("caught error while processing response: {}", self.0);

        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorDto {
                message: format!("{}", self.0),
            }),
        )
            .into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
