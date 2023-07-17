use sqlx::mysql::MySqlPool;

use actix_web::{web, App, HttpServer};
use crate::handler;
use std::sync::{RwLock};

pub struct AppState {
    pub conf : super::config::Config,
    pub dbp: sqlx::mysql::MySqlPool,
    pub redis: RwLock<redis::Connection>,
}
#[actix_web::main]
pub async fn init(conf : super::config::Config) -> std::io::Result<()> {
    let db_result = MySqlPool::connect(conf.db.data_source.as_str()).await;
    if db_result.is_err() {
        panic!("error connecting to db {}", db_result.as_ref().unwrap_err())
    }

    let redis_result = redis::Client::open(conf.clone().redis.address);
    if redis_result.is_err() {
        panic!("error connecting to redis {}", redis_result.as_ref().unwrap_err())
    }
    let con_result = redis_result.unwrap().get_connection();
    if con_result.is_err() {
        panic!("error in redis connection")
    }

    let app_state = web::Data::new(AppState { 
        conf: conf.clone(),
        dbp: db_result.unwrap(),
        redis: con_result.unwrap().into()
    });

    
    HttpServer::new(move || {
        App::new()
        .app_data(app_state.clone())
        .route("/api/v1/health", web::get().to(handler::health))
        .route("/api/v1/info", web::get().to(handler::info))
        .route("/api/v1/login", web::post().to(handler::login))
        .route("/api/v1/verify", web::get().to(handler::verify_token))
        .route("/api/v1/token", web::get().to(handler::get_token))
        .route("/api/v1/profile", web::get().to(handler::get_profile))
        .route("/api/v1/profile", web::put().to(handler::set_profile))
    })
    .bind(conf.server.address)?
    .run()
    .await
}