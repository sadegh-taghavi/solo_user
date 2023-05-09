use sqlx::mysql::MySqlPool;

use actix_web::{web, App, HttpServer};
use crate::handler;

#[derive(Clone)]
pub struct AppState {
    pub conf : super::config::Config,
    pub dbp: sqlx::mysql::MySqlPool,
}
#[actix_web::main]
pub async fn init(conf : super::config::Config) -> std::io::Result<()> {
    let result = MySqlPool::connect(conf.db.data_source.as_str()).await;
    if result.is_err() {
        panic!("error connecting to db {}", result.as_ref().unwrap_err())
    }
    let app_state = web::Data::new(AppState { conf: conf.clone(), dbp: result.unwrap() });

    HttpServer::new(move || {
        App::new()
        .app_data(app_state.clone())
        .route("/api/v1/health", web::get().to(handler::helth))
        .route("/api/v1/info", web::get().to(handler::info))
        .route("/api/v1/login", web::post().to(handler::login))
        .route("/api/v1/verify", web::get().to(handler::verify_token))
        .route("/api/v1/profile", web::put().to(handler::set_profile))
    })
    .bind(conf.server.address)?
    .run()
    .await
}