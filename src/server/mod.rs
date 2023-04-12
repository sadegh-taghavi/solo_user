use serde::Serialize;
// use serde::Deserialize;

use actix_web::get;
use actix_web::Responder;
use actix_web::HttpServer;
use actix_web::App;
use actix_web::HttpResponse;

use chrono::prelude::Utc;

// #[path = "../config/mod.rs"] mod config;


#[get("/api/v1/health")]
async fn helth() -> impl Responder {
    #[derive(Debug, Serialize)]
    struct Health {
        status: String,
    }

    let health = Health {
        status: "ok".to_string(),
    };
    HttpResponse::Ok().json(health)
}



#[get("/api/v1/info")]
async fn info() -> impl Responder {  
    #[derive(Debug, Serialize)]
    struct Info {
        version: String,
        time: String,
    }

    let info = Info {
        version: "0.0.1".to_string(),
        time: Utc::now().to_string(),
    };
    HttpResponse::Ok().json(info)
}

#[actix_web::main]
pub async fn init(conf : super::config::Config) -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new().service(helth).service(info)
    })
    .bind(conf.server.address)?
    .run()
    .await
}