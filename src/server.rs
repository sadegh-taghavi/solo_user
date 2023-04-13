use serde::Serialize;
// use serde::Deserialize;

use actix_web::{Responder, get, web, App, HttpResponse, HttpServer};

use chrono::prelude::Utc;

use sqlx::{mysql::MySqlPool};

#[derive(Clone)]
struct AppState {
    conf : super::config::Config,
    dbp: sqlx::mysql::MySqlPool,
}

#[get("/api/v1/health")]
async fn helth_handler() -> impl Responder {
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
async fn info_handler() -> impl Responder {  
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

#[actix_web::main]
pub async fn init(conf : super::config::Config) -> std::io::Result<()> {

    let result = MySqlPool::connect(conf.db.datasource.as_str()).await;
    if result.is_err() {
        panic!("error connecting to db {}", result.as_ref().unwrap_err())
    }
    let app_state = web::Data::new(AppState { conf: conf.clone(), dbp: result.unwrap() });

    HttpServer::new(move || {
        App::new()
        .app_data(app_state.clone())
        .service(helth_handler)
        .service(info_handler)
    })
    .bind(conf.server.address)?
    .run()
    .await
}