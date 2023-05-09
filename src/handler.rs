use jsonwebtoken::{encode, Header, EncodingKey};
use serde::{Serialize};
use uuid::Uuid;

use actix_web::{Responder, web, HttpResponse, HttpRequest, HttpMessage};
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

            #[derive(serde::Deserialize, serde::Serialize, sqlx::FromRow, Clone)]
            struct User {
                uuid: String,
                email: String,
                name: String,
            }

            let userinfo = result.unwrap();
            let result = sqlx::query_as::<_, User>("SELECT uuid, email, name FROM users WHERE email = ?").bind(userinfo.id.clone())
            .fetch_all(&app_state.dbp)
            .await;
            if result.is_err() {
                error!("error in query {}", result.as_ref().err().unwrap() );
                return HttpResponse::InternalServerError().body("");
            }
    
            let mut user = User{
                uuid:String::from(""),
                email: String::from(""),
                name:String::from(""),
            };
            if result.as_ref().unwrap().len() > 0 {
                user = result.as_ref().unwrap().first().unwrap().clone();
            }else {
                user.email = userinfo.id.clone();
                user.name = userinfo.id.clone();
                user.uuid = Uuid::new_v4().to_string();


                let result = sqlx::query!( "INSERT INTO users (uuid, email, name) VALUES (?, ?, ?)", user.uuid, user.email, user.name)
                .execute(&app_state.dbp)
                .await;

                if result.is_err() {
                    error!("error in insert {}", result.as_ref().unwrap_err() );
                    return HttpResponse::InternalServerError().body("");
                }
            }
            
            let my_claims = crate::model::TokenClaims {
                sub: user.uuid.clone(),
                name: user.name.clone(),
                email: user.email.clone(),
                iat: Utc::now().checked_sub_signed(Duration::minutes(10)).unwrap().timestamp(),
                exp: Utc::now().checked_add_signed(Duration::minutes(app_state.conf.jwt.expire.clone())).unwrap().timestamp(),
            };
            let token = encode(&Header::default(), &my_claims, &EncodingKey::from_secret(app_state.conf.jwt.secret.as_ref())).unwrap();

           return HttpResponse::Ok().body(token);
        }
    }

}


pub async fn set_profile(req: HttpRequest,/*signup_request: web::Json<SignupRequest>,*/ app_state: web::Data<crate::server::AppState>, claim: crate::model::TokenClaims) -> impl Responder {  

    
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

    // let (authorize_url, _)= google_client(app_state.clone())
    // .authorize_url(CsrfToken::new_random)
    // .add_scope(Scope::new( "https://www.googleapis.com/auth/plus.me".to_string()))
    // .url();

    #[derive(Debug, Serialize)]
    struct SignupResponse {
        url: String,
    }

    HttpResponse::Ok().json(SignupResponse {
        url: claim.email,
    })   

}
