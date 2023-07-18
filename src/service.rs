use chrono::Duration;
use chrono::prelude::Utc;

use oauth2::{basic::BasicClient, TokenResponse};
use jsonwebtoken::{encode, Header, EncodingKey};
use reqwest::{Client, Url};
use uuid::Uuid;

use redis::Commands;

// Alternatively, this can be oauth2::curl::http_client or a custom.
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl,
    RevocationUrl, Scope, TokenUrl,
    reqwest::async_http_client,
};

use crate::model::{ProfileInfo, ErrorResponse};

pub fn google_client(oauth: &crate::config::OAuth ) -> BasicClient {
    let google_client_id = ClientId::new( oauth.google_client_id.clone());   
    let google_client_secret = ClientSecret::new( oauth.google_client_secret.clone() );
    let auth_url = AuthUrl::new(oauth.auth_url.clone());
    let token_url = TokenUrl::new(oauth.token_url.clone());    
    BasicClient::new(google_client_id, Some(google_client_secret), auth_url.unwrap(), Some(token_url.unwrap())).
    set_redirect_uri( RedirectUrl::new(oauth.redirect_url.clone()).unwrap(),)
    .set_revocation_uri(RevocationUrl::new(oauth.revokation_url.clone()).unwrap())
}

pub fn generate_token(profile: &ProfileInfo, jwt: &crate::config::JWT) -> String {
    let my_claims = crate::model::TokenClaims {
        sub: profile.uuid.clone(),
        name: profile.name.clone(),
        email: profile.email.clone(),
        iat: Utc::now().checked_sub_signed(Duration::minutes(10)).unwrap().timestamp(),
        exp: Utc::now().checked_add_signed(Duration::minutes(jwt.expire.clone())).unwrap().timestamp(),
    };
    encode(&Header::default(), &my_claims, &EncodingKey::from_secret(jwt.secret.as_ref())).unwrap()
}

pub async fn login(app_state: &crate::server::AppState) ->  Result<crate::model::SignupResponse, crate::model::ErrorResponse> {

    let (authorize_url, csrf_token)= crate::service::google_client(&app_state.conf.oauth)
    .authorize_url(CsrfToken::new_random)
    .add_scope(Scope::new( "https://www.googleapis.com/auth/plus.me".to_string()))
    .url();

    let csrf_token_string = serde_json::to_string_pretty(&csrf_token).unwrap();
    
    Result::Ok( crate::model::SignupResponse {
        refid: csrf_token_string.replace("\"", ""),
        url: authorize_url.to_string(),
    } )
}

pub async fn verify_token(query: &crate::model::VerifyQuery, app_state: &crate::server::AppState) ->  Result<String, crate::model::ErrorResponse> {

    let client = crate::service::google_client(&app_state.conf.oauth);
    let token_res = client.exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(async_http_client)
        .await;

    if token_res.is_err() {
        error!("response {:#?}", token_res.as_ref().err().unwrap() );
        return Result::Err( ErrorResponse { status: "500".to_string(), message: "token_res".to_string() })
    }else {
        let client = Client::new();
        let url = Url::parse(app_state.conf.oauth.userinfo_url.clone().as_str()).unwrap();
        let response = client.get(url).bearer_auth(token_res.unwrap().access_token().secret().clone()).send().await;

        if response.is_err() {
            error!("error in query {}", response.as_ref().err().unwrap() );
            return Result::Err( ErrorResponse { status: "500".to_string(), message: "response".to_string() })   
        }
       
        let result: Result<crate::model::UserInfo, serde_json::Error> = serde_json::from_str(response.unwrap().text().await.unwrap().as_str());
        if result.is_err() {
            error!("error in query {}", result.err().unwrap() );
            return Result::Err( ErrorResponse { status: "500".to_string(), message: "userinfo".to_string() })   
        }else {
         
            let userinfo = result.unwrap();
            let result = sqlx::query_as::<_, crate::model::ProfileInfo>("SELECT uuid, email, name FROM users WHERE email = ?").bind(userinfo.id.clone())
            .fetch_all(&app_state.dbp)
            .await;
            if result.is_err() {
                error!("error in query {}", result.as_ref().err().unwrap() );
                return Result::Err( ErrorResponse { status: "500".to_string(), message: "".to_string() })   
            }
    
            let mut profile = crate::model::ProfileInfo{
                uuid:String::from(""),
                email: String::from(""),
                name:String::from(""),
            };
            if result.as_ref().unwrap().len() > 0 {
                profile = result.as_ref().unwrap().first().unwrap().clone();
            }else {
                profile.email = userinfo.id.clone();
                profile.name = userinfo.id.clone();
                profile.uuid = Uuid::new_v4().to_string();


                let result = sqlx::query!( "INSERT INTO users (uuid, email, name) VALUES (?, ?, ?)", profile.uuid, profile.email, profile.name)
                .execute(&app_state.dbp)
                .await;

                if result.is_err() {
                    error!("error in insert {}", result.as_ref().unwrap_err() );
                    return Result::Err( ErrorResponse { status: "500".to_string(), message: "".to_string() })   
                }
            }

            let result: Result<(), redis::RedisError> = app_state.redis.write().unwrap().set_ex( query.state.clone(), crate::service::generate_token(&profile, &app_state.conf.jwt),
             app_state.clone().conf.redis.token_retrive_timeout_secound.try_into().unwrap() );
            if result.is_err() {
                error!("response {:#?}", result.as_ref().err().unwrap() );
                return Result::Err( ErrorResponse { status: "500".to_string(), message: "redis set".to_string() })   
            }

            Result::Ok("You are in! Please back to the app.".to_string()) 
        }
    }
}

pub async fn get_token(query: &crate::model::TokenQuery, app_state: &crate::server::AppState) ->  Result<String, crate::model::ErrorResponse> {

    if query.refid.is_empty() {
        return Result::Err( ErrorResponse { status: "400".to_string(), message: "ref is empty".to_string() })
    }else {
        let result: Result<Option<String>, redis::RedisError> = app_state.redis.write().unwrap().get( query.refid.clone());
        if result.is_err() {
            error!("response {:#?}", result.as_ref().err().unwrap() );
            return Result::Err( ErrorResponse { status: "500".to_string(), message: "redis set".to_string() })   
        }
        let token = match result.unwrap() {
            Some(t) => t,
            None => {
                return Result::Err( ErrorResponse { status: "400".to_string(), message: "ref not found".to_string() })
            }
        };

        Result::Ok( token )
    }
}

pub async fn get_profile(app_state: &crate::server::AppState, claims: &crate::model::TokenClaims) ->  Result<crate::model::ProfileInfo, crate::model::ErrorResponse> {

    let result = sqlx::query_as::<_, crate::model::ProfileInfo>("SELECT uuid, email, name FROM users WHERE uuid = ?").bind(claims.sub.clone())
            .fetch_all(&app_state.dbp)
            .await;
            if result.is_err() {
                error!("error in query {}", result.as_ref().err().unwrap() );
                return Result::Err( ErrorResponse { status: "500".to_string(), message: "".to_string() })   
            }
    
    let mut profile = crate::model::ProfileInfo{
        uuid:String::from(""),
        email: String::from(""),
        name:String::from(""),
    };
    if result.as_ref().unwrap().len() > 0 {
        profile = result.as_ref().unwrap().first().unwrap().clone();
    }
    Result::Ok( profile )
}


pub async fn set_profile(profile_request: &crate::model::ProfileRequest, app_state: &crate::server::AppState, claims: &crate::model::TokenClaims) ->  Result<String, crate::model::ErrorResponse> {

    let result = sqlx::query!("SELECT name FROM users WHERE name = ? and uuid != ?", profile_request.name, claims.sub)
    .fetch_optional(&app_state.dbp)
    .await;

    if result.is_err() {
        error!("error in query {}", result.as_ref().unwrap_err() );
        return Result::Err( ErrorResponse { status: "500".to_string(), message: "".to_string() })
    }

    if result.as_ref().unwrap().is_some() {
        return Result::Err( ErrorResponse { status: "400".to_string(), message: "Name already taken".to_string() })
    }

    let result = sqlx::query!( "update users set name = ? where uuid = ?", profile_request.name, claims.sub)
    .execute(&app_state.dbp)
    .await;

    if result.is_err() {
        error!("error in insert {}", result.as_ref().unwrap_err() );
        return Result::Err( ErrorResponse { status: "500".to_string(), message: "".to_string() })
    }

    let result = sqlx::query_as::<_, crate::model::ProfileInfo>("SELECT uuid, email, name FROM users WHERE uuid = ?").bind(claims.sub.clone())
            .fetch_all(&app_state.dbp)
            .await;
            if result.is_err() {
                error!("error in query {}", result.as_ref().err().unwrap() );
                return Result::Err( ErrorResponse { status: "500".to_string(), message: "".to_string() })
            }
    
    let mut profile = crate::model::ProfileInfo{
        uuid:String::from(""),
        email: String::from(""),
        name:String::from(""),
    };
    if result.as_ref().unwrap().len() > 0 {
        profile = result.as_ref().unwrap().first().unwrap().clone();
    } 

    Result::Ok( generate_token( &profile, &app_state.conf.jwt ))
}