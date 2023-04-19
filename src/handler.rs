use jsonwebtoken::{encode, Header, EncodingKey};
use serde::{Serialize, Deserialize};
use serde_json::json;
use rand_core::{OsRng, RngCore};
use bcrypt::{hash, verify};

use actix_web::{Responder, get, web, App, HttpResponse, HttpServer};

use oauth2::{basic::BasicClient, revocation::StandardRevocableToken, TokenResponse};
// Alternatively, this can be oauth2::curl::http_client or a custom.
use oauth2::reqwest::http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    RevocationUrl, Scope, TokenUrl,
};
use url::Url;

use chrono::prelude::Utc;

pub async fn helth() -> impl Responder {
    #[derive(Debug, Serialize)]
    struct Health {
        status: String,
    }

    let health = Health {
        status: "ok".to_string(),
    };
    HttpResponse::Ok().json(health)
}

pub async fn info() -> impl Responder {  
    #[derive(Debug, Serialize)]
    struct Info {
        info: String,
        version: String,
        time: String,
    }

    let info = Info {
        info: "user authentication service".to_string(),
        version: "0.0.1".to_string(),
        time: Utc::now().to_string(),
    };
    HttpResponse::Ok().json(info)
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct SignupRequest {
    email: String,
    name: String,
    password: String,
}

pub async fn signup(signup_request: web::Json<SignupRequest>, state: web::Data<crate::server::AppState>) -> impl Responder {  

    let result = sqlx::query!("SELECT email FROM users WHERE email = ?", signup_request.email)
    .fetch_optional(&state.dbp)
    .await;
   
    if result.is_err() {
        error!("error in query {}", result.as_ref().unwrap_err() );
        return HttpResponse::InternalServerError().body("");
    }
    
    if result.as_ref().unwrap().is_some() {
        return HttpResponse::BadRequest().body("Email already exists");
    }

    let result = sqlx::query!("SELECT name FROM users WHERE name = ?", signup_request.name)
    .fetch_optional(&state.dbp)
    .await;
   
    if result.is_err() {
        error!("error in query {}", result.as_ref().unwrap_err() );
        return HttpResponse::InternalServerError().body("");
    }
    
    if result.as_ref().unwrap().is_some() {
        return HttpResponse::BadRequest().body("Name already taken");
    }

    let mut rng = OsRng;
    let mut bytes = [0u8; 10];
    rng.fill_bytes(&mut bytes);
    let token: String = bytes
        .iter()
        .map(|b| char::from_digit((b % 10) as u32, 10).unwrap())
        .collect();

    let hashed_password = hash(signup_request.password.clone(), 10).unwrap();

    let req = SignupRequest {
        email:signup_request.email.clone(),
        name: signup_request.name.clone(),
        password: hashed_password,
    };

    let json_object = json!(req);
    let result = serde_json::to_string(&json_object);
    if result.is_err() {
        error!("error in serialize {}", result.as_ref().unwrap_err() );
        return HttpResponse::InternalServerError().body("");
    }

    let result = sqlx::query!(
        "INSERT INTO verify (token, data) VALUES (?, ?)",
        token, result.unwrap()
    )
    .execute(&state.dbp)
    .await;

    if result.is_err() {
        error!("error in insert {}", result.as_ref().unwrap_err() );
        return HttpResponse::InternalServerError().body("");
    }

    let google_client_id = ClientId::new( state.conf.oauth.googleclientid);
    
    
    let google_client_secret = ClientSecret::new( state.conf.oauth.googleclientsecret );
       
    let auth_url = AuthUrl::new(state.conf.oauth.authurl);
    if auth_url.is_err() {
        error!("error in auth {}", auth_url.as_ref().unwrap_err() );
        return HttpResponse::InternalServerError().body("");
    }
    let token_url = TokenUrl::new(state.conf.oauth.tokenurl);
    if token_url.is_err() {
        error!("error in auth {}", token_url.as_ref().unwrap_err() );
        return HttpResponse::InternalServerError().body("");
    }
    // Set up the config for the Google OAuth2 process.
    let client = BasicClient::new(google_client_id, Some(google_client_secret), auth_url, Some(token_url))

    // This example will be running its own server at localhost:8080.
    // See below for the server implementation.
    .set_redirect_uri(
        RedirectUrl::new("http://localhost:8080".to_string()).expect("Invalid redirect URL"),
    )
    // Google supports OAuth 2.0 Token Revocation (RFC-7009)
    .set_revocation_uri(
        RevocationUrl::new("https://oauth2.googleapis.com/revoke".to_string())
            .expect("Invalid revocation endpoint URL"),
    );

    // Google supports Proof Key for Code Exchange (PKCE - https://oauth.net/2/pkce/).
    // Create a PKCE code verifier and SHA-256 encode it as a code challenge.
    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the authorization URL to which we'll redirect the user.
    let (authorize_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        // This example is requesting access to the "calendar" features and the user's profile.
        .add_scope(Scope::new(
            "https://www.googleapis.com/auth/calendar".to_string(),
        ))
        .add_scope(Scope::new(
            "https://www.googleapis.com/auth/plus.me".to_string(),
        ))
        .set_pkce_challenge(pkce_code_challenge)
        .url();

    println!(
        "Open this URL in your browser:\n{}\n",
        authorize_url.to_string()
    );



    HttpResponse::Ok().body("Verify by email.")

}


#[derive(serde::Deserialize, serde::Serialize)]
pub struct VerifyRequest {
    token: String,
}

pub async fn verify_token(verify_request: web::Json<VerifyRequest>, state: web::Data<crate::server::AppState>) -> impl Responder {  

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


    HttpResponse::Ok().body("Registerd")
}