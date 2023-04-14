use serde::{Serialize, Deserialize};
use serde_json::json;
use rand_core::{OsRng, RngCore};
use bcrypt::{hash, verify};

use actix_web::{Responder, get, web, App, HttpResponse, HttpServer};

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
        warn!("error in query {}", result.as_ref().unwrap_err() );
        return HttpResponse::InternalServerError().body("");
    }
    
    if result.as_ref().unwrap().is_some() {
        return HttpResponse::BadRequest().body("Email already exists");
    }

    let mut rng = OsRng;
    let mut bytes = [0u8; 6];
    rng.fill_bytes(&mut bytes);
    let token: String = bytes
        .iter()
        .map(|b| (b % 10) as char)
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
        warn!("error in serialize {}", result.as_ref().unwrap_err() );
        return HttpResponse::InternalServerError().body("");
    }

    let result = sqlx::query!(
        "INSERT INTO verify (token, data) VALUES (?, ?)",
        token, result.unwrap()
    )
    .execute(&state.dbp)
    .await;

    if result.is_err() {
        warn!("error in insert {}", result.as_ref().unwrap_err() );
        return HttpResponse::InternalServerError().body("");
    }

    HttpResponse::Ok().body("Verify email.")

}