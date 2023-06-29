use jsonwebtoken::{encode, Header, EncodingKey};
use serde::{Serialize};
use uuid::Uuid;

use actix_web::{Responder, web, HttpResponse};
use reqwest::{Client, Url};

use oauth2::{basic::BasicClient, TokenResponse};
// Alternatively, this can be oauth2::curl::http_client or a custom.
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl,
    RevocationUrl, Scope, TokenUrl,
    reqwest::async_http_client,
};

use chrono::Duration;
use chrono::prelude::Utc;

use crate::model::ProfileInfo;

use redis::Commands;

pub async fn helth() -> impl Responder {
    #[derive(Debug, Serialize)]
    struct Health {
        status: String,
    }

    HttpResponse::Ok().json(Health {
        status: "ok".to_string(),
    })
}

pub async fn info() -> impl Responder {  
    #[derive(Debug, Serialize)]
    struct Info {
        info: String,
        version: String,
        time: String,
    }

    HttpResponse::Ok().json(Info {
        info: "user authentication service".to_string(),
        version: "0.0.1".to_string(),
        time: Utc::now().to_string(),
    })
}

fn google_client(app_state: web::Data<crate::server::AppState>) -> BasicClient {
    let google_client_id = ClientId::new( app_state.conf.oauth.google_client_id.clone());   
    let google_client_secret = ClientSecret::new( app_state.conf.oauth.google_client_secret.clone() );
    let auth_url = AuthUrl::new(app_state.conf.oauth.auth_url.clone());
    let token_url = TokenUrl::new(app_state.conf.oauth.token_url.clone());    
    BasicClient::new(google_client_id, Some(google_client_secret), auth_url.unwrap(), Some(token_url.unwrap())).
    set_redirect_uri( RedirectUrl::new(app_state.conf.oauth.redirect_url.clone()).unwrap(),)
    .set_revocation_uri(RevocationUrl::new(app_state.conf.oauth.revokation_url.clone()).unwrap())
}

fn generate_token(profile: ProfileInfo, app_state: web::Data<crate::server::AppState>) -> String {
    let my_claims = crate::model::TokenClaims {
        sub: profile.uuid.clone(),
        name: profile.name.clone(),
        email: profile.email.clone(),
        iat: Utc::now().checked_sub_signed(Duration::minutes(10)).unwrap().timestamp(),
        exp: Utc::now().checked_add_signed(Duration::minutes(app_state.conf.jwt.expire.clone())).unwrap().timestamp(),
    };
    encode(&Header::default(), &my_claims, &EncodingKey::from_secret(app_state.conf.jwt.secret.as_ref())).unwrap()
}

pub async fn login(app_state: web::Data<crate::server::AppState>) -> impl Responder {  

    let (authorize_url, csrf_token)= google_client(app_state.clone())
    .authorize_url(CsrfToken::new_random)
    .add_scope(Scope::new( "https://www.googleapis.com/auth/plus.me".to_string()))
    .url();

    #[derive(Debug, Serialize)]
    struct SignupResponse {
        refid: String,
        url: String,
    }
    
    let csrf_token_string = serde_json::to_string_pretty(&csrf_token).unwrap();
    
    HttpResponse::Ok().json(SignupResponse {
        refid: csrf_token_string.replace("\"", ""),
        url: authorize_url.to_string(),
    })

}


pub async fn verify_token(query: web::Query<crate::model::VerifyQuery>, app_state: web::Data<crate::server::AppState>) -> impl Responder {  

    let client = google_client(app_state.clone());
    let token_res = client.exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(async_http_client)
        .await;

    if token_res.is_err() {
        format!("response {:#?}", token_res.as_ref().err().unwrap() );
        return HttpResponse::InternalServerError().body("token_res")
    }else {
        let client = Client::new();
        let url = Url::parse(app_state.conf.oauth.userinfo_url.clone().as_str()).unwrap();
        let response = client.get(url).bearer_auth(token_res.unwrap().access_token().secret().clone()).send().await;

        if response.is_err() {
            error!("error in query {}", response.as_ref().err().unwrap() );
            return HttpResponse::InternalServerError().body( format!("response {:#?}", response.err()))    
        }
       
        let result: Result<crate::model::UserInfo, serde_json::Error> = serde_json::from_str(response.unwrap().text().await.unwrap().as_str());
        if result.is_err() {
            error!("error in query {}", result.err().unwrap() );
            return HttpResponse::InternalServerError().body("userinfo")          
        }else {

          
            let userinfo = result.unwrap();
            let result = sqlx::query_as::<_, crate::model::ProfileInfo>("SELECT uuid, email, name FROM users WHERE email = ?").bind(userinfo.id.clone())
            .fetch_all(&app_state.dbp)
            .await;
            if result.is_err() {
                error!("error in query {}", result.as_ref().err().unwrap() );
                return HttpResponse::InternalServerError().body("");
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
                    return HttpResponse::InternalServerError().body("");
                }
            }

            let result: Result<(), redis::RedisError> = app_state.redis.write().unwrap().set_ex( query.state.clone(), generate_token(profile, app_state.clone()),
             app_state.clone().conf.redis.token_retrive_timeout_secound.try_into().unwrap() );
            if result.is_err() {
                format!("response {:#?}", result.as_ref().err().unwrap() );
                return HttpResponse::InternalServerError().body("redis set")
            }

            return HttpResponse::Ok().body("You are in! Please back to the app.");
        }
    }

}


pub async fn get_token(query: web::Query<crate::model::TokenQuery>, app_state: web::Data<crate::server::AppState>) -> impl Responder {  

    if query.refid.is_empty() {
        return HttpResponse::BadRequest().body("ref is empty")
    }else {
            let result: Result<Option<String>, redis::RedisError> = app_state.redis.write().unwrap().get( query.refid.clone());
            if result.is_err() {
                format!("response {:#?}", result.as_ref().err().unwrap() );
                return HttpResponse::BadRequest().body("redis get")
            }

            let token = match result.unwrap() {
                Some(t) => t,
                None => {
                    return HttpResponse::BadRequest().body("ref not found");
                }
            };

            return HttpResponse::Ok().body( token );
        }

}


pub async fn get_profile(/*req: HttpRequest,*/ app_state: web::Data<crate::server::AppState>, claims: crate::model::TokenClaims) -> impl Responder {  

   let result = sqlx::query_as::<_, crate::model::ProfileInfo>("SELECT uuid, email, name FROM users WHERE uuid = ?").bind(claims.sub.clone())
            .fetch_all(&app_state.dbp)
            .await;
            if result.is_err() {
                error!("error in query {}", result.as_ref().err().unwrap() );
                return HttpResponse::InternalServerError().body("");
            }
    
    let mut profile = crate::model::ProfileInfo{
        uuid:String::from(""),
        email: String::from(""),
        name:String::from(""),
    };
    if result.as_ref().unwrap().len() > 0 {
        profile = result.as_ref().unwrap().first().unwrap().clone();
    }
    HttpResponse::Ok().json(profile)   
}

pub async fn set_profile(/*req: HttpRequest,*/profile_request: web::Json<crate::model::ProfileRequest>, app_state: web::Data<crate::server::AppState>, claims: crate::model::TokenClaims) -> impl Responder {  

    let result = sqlx::query!("SELECT name FROM users WHERE name = ? and uuid != ?", profile_request.name, claims.sub)
    .fetch_optional(&app_state.dbp)
    .await;

    if result.is_err() {
        error!("error in query {}", result.as_ref().unwrap_err() );
        return HttpResponse::InternalServerError().body("");
    }

    if result.as_ref().unwrap().is_some() {
        return HttpResponse::BadRequest().body("Name already taken");
    }

    let result = sqlx::query!( "update users set name = ? where uuid = ?", profile_request.name, claims.sub)
    .execute(&app_state.dbp)
    .await;

    if result.is_err() {
        error!("error in insert {}", result.as_ref().unwrap_err() );
        return HttpResponse::InternalServerError().body("");
    }

    let result = sqlx::query_as::<_, crate::model::ProfileInfo>("SELECT uuid, email, name FROM users WHERE uuid = ?").bind(claims.sub.clone())
            .fetch_all(&app_state.dbp)
            .await;
            if result.is_err() {
                error!("error in query {}", result.as_ref().err().unwrap() );
                return HttpResponse::InternalServerError().body("");
            }
    
    let mut profile = crate::model::ProfileInfo{
        uuid:String::from(""),
        email: String::from(""),
        name:String::from(""),
    };
    if result.as_ref().unwrap().len() > 0 {
        profile = result.as_ref().unwrap().first().unwrap().clone();
    }  

    return HttpResponse::Ok().body(generate_token( profile, app_state ));

}
