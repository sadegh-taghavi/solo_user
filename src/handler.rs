use serde::Serialize;
// use serde::Deserialize;

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
