use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub status: String,
    pub message: String,
}

#[derive(serde::Deserialize, serde::Serialize, Clone)]
pub struct UserInfo {
    pub id: String,
    pub picture: String,
}

#[derive(serde::Deserialize, serde::Serialize, Clone)]
pub struct VerifyQuery {
    pub state: String,
    pub code: String,
    pub scope: String,
}

#[derive(serde::Deserialize, serde::Serialize, Clone)]
pub struct TokenQuery {
    pub refid: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub name: String,
    pub email: String,
    pub iat: i64,
    pub exp: i64,
}

#[derive(serde::Deserialize, serde::Serialize, sqlx::FromRow, Clone)]
pub struct ProfileInfo {
    pub uuid: String,
    pub email: String,
    pub name: String,
}

#[derive(serde::Deserialize, serde::Serialize, Clone)]
pub struct ProfileRequest {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct SignupResponse {
    pub refid: String,
    pub url: String,
}