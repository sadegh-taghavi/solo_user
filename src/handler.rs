use jsonwebtoken::{encode, Header, EncodingKey};
use serde::{Serialize, Deserialize};
use serde_json::json;
use rand_core::{OsRng, RngCore};
use bcrypt::{hash, verify};

use actix_web::{Responder, get, web, App, HttpResponse, HttpServer};
use reqwest::{Client, Url};

use oauth2::{basic::BasicClient, basic::BasicTokenType, revocation::StandardRevocableToken, TokenResponse};
// Alternatively, this can be oauth2::curl::http_client or a custom.
use oauth2::reqwest::http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    RevocationUrl, Scope, TokenUrl,
    reqwest::async_http_client,
};

use chrono::prelude::Utc;

use super::AppState;

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

// #[derive(serde::Deserialize, serde::Serialize)]
// pub struct SignupRequest {
//     email: String,
//     name: String,
//     password: String,
// }

fn google_client(app_state: web::Data<crate::server::AppState>) -> BasicClient {
    let google_client_id = ClientId::new( app_state.conf.oauth.google_client_id.clone());   
    let google_client_secret = ClientSecret::new( app_state.conf.oauth.google_client_secret.clone() );
    let auth_url = AuthUrl::new(app_state.conf.oauth.auth_url.clone());
    let token_url = TokenUrl::new(app_state.conf.oauth.token_url.clone());    
    BasicClient::new(google_client_id, Some(google_client_secret), auth_url.unwrap(), Some(token_url.unwrap())).
    set_redirect_uri( RedirectUrl::new(app_state.conf.oauth.redirect_url.clone()).unwrap(),)
    .set_revocation_uri(RevocationUrl::new(app_state.conf.oauth.revokation_url.clone()).unwrap())
}

pub async fn login(/*signup_request: web::Json<SignupRequest>,*/ app_state: web::Data<crate::server::AppState>) -> impl Responder {  

    // let result = sqlx::query!("SELECT email FROM users WHERE email = ?", signup_request.email)
    // .fetch_optional(&state.dbp)
    // .await;
   
    // if result.is_err() {
    //     error!("error in query {}", result.as_ref().unwrap_err() );
    //     return HttpResponse::InternalServerError().body("");
    // }
    
    // if result.as_ref().unwrap().is_some() {
    //     return HttpResponse::BadRequest().body("Email already exists");
    // }

    // let result = sqlx::query!("SELECT name FROM users WHERE name = ?", signup_request.name)
    // .fetch_optional(&state.dbp)
    // .await;
   
    // if result.is_err() {
    //     error!("error in query {}", result.as_ref().unwrap_err() );
    //     return HttpResponse::InternalServerError().body("");
    // }
    
    // if result.as_ref().unwrap().is_some() {
    //     return HttpResponse::BadRequest().body("Name already taken");
    // }

    // let mut rng = OsRng;
    // let mut bytes = [0u8; 10];
    // rng.fill_bytes(&mut bytes);
    // let token: String = bytes
    //     .iter()
    //     .map(|b| char::from_digit((b % 10) as u32, 10).unwrap())
    //     .collect();

    // let hashed_password = hash(signup_request.password.clone(), 10).unwrap();

    // let req = SignupRequest {
    //     email:signup_request.email.clone(),
    //     name: signup_request.name.clone(),
    //     password: hashed_password,
    // };

    // let json_object = json!(req);
    // let result = serde_json::to_string(&json_object);
    // if result.is_err() {
    //     error!("error in serialize {}", result.as_ref().unwrap_err() );
    //     return HttpResponse::InternalServerError().body("");
    // }

    // let result = sqlx::query!(
    //     "INSERT INTO verify (token, data) VALUES (?, ?)",
    //     token, result.unwrap()
    // )
    // .execute(&state.dbp)
    // .await;

    // if result.is_err() {
    //     error!("error in insert {}", result.as_ref().unwrap_err() );
    //     return HttpResponse::InternalServerError().body("");
    // }

    let (authorize_url, _)= google_client(app_state.clone())
    .authorize_url(CsrfToken::new_random)
    .add_scope(Scope::new( "https://www.googleapis.com/auth/plus.me".to_string()))
    .url();

    #[derive(Debug, Serialize)]
    struct SignupResponse {
        url: String,
    }

    HttpResponse::Ok().json(SignupResponse {
        url: authorize_url.to_string(),
    })   

}


// #[derive(serde::Deserialize, serde::Serialize)]
// pub struct VerifyRequest {
//     token: String,
// }


#[derive(serde::Deserialize, serde::Serialize, Clone)]
struct UserInfo {
    id: String,
    picture: String,
}

#[derive(serde::Deserialize, serde::Serialize, Clone)]
pub struct VerifyQuery {
    state: String,
    code: String,
    scope: String,
}

pub async fn verify_token(query: web::Query<VerifyQuery>, app_state: web::Data<crate::server::AppState>) -> impl Responder {  

    // let result = sqlx::query!("SELECT data FROM verify WHERE token = ?", verify_request.token)
    // .fetch_optional(&state.dbp)
    // .await;
   
    // if result.is_err() {
    //     error!("error in query {}", result.as_ref().unwrap_err() );
    //     return HttpResponse::InternalServerError().body("");
    // }
    
    // if result.as_ref().unwrap().is_some() {
    //     return HttpResponse::BadRequest().body("Email already exists");
    // }

    // let result = serde_json::to_string(&json_object);
    // if result.is_err() {
    //     error!("error in serialize {}", result.as_ref().unwrap_err() );
    //     return HttpResponse::InternalServerError().body("");
    // }


    // let my_claims = Claims { sub: "1234567890", name: "John Doe", iat: 1516239022 };
    // let token = encode(&Header::default(), &my_claims, &EncodingKey::from_secret(state.conf.jwt.secret.as_ref())).unwrap();


    // HttpResponse::Ok().body("Registerd")

    let client = google_client(app_state.clone());
    let token_res = client.exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(async_http_client)
        .await;

    if token_res.is_err() {
        return HttpResponse::BadRequest().body("token_res")
    }else {
        let client = Client::new();
        let url = Url::parse(app_state.conf.oauth.userinfo_url.clone().as_str()).unwrap();
        let response = client.get(url).bearer_auth(token_res.unwrap().access_token().secret().clone()).send().await;

        if response.is_err() {
            return HttpResponse::BadRequest().body( format!("response {:#?}", response.err()))    
        }
       
        let userinfo: Result<UserInfo, serde_json::Error> = serde_json::from_str(response.unwrap().text().await.unwrap().as_str());
        if userinfo.is_err() {
            return HttpResponse::BadRequest().body("userinfo")          
        }else {
            return HttpResponse::Ok().json(userinfo.unwrap());
        }
    }

}
