use sqlx::mysql::MySqlPool;

use actix_web::{web, App, HttpServer};
#[path ="handler.rs"] mod handler;

#[derive(Clone)]
pub struct AppState {
    conf : super::config::Config,
    dbp: sqlx::mysql::MySqlPool,
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
        .route("/api/v1/health", web::get().to(handler::helth))
        .route("/api/v1/info", web::get().to(handler::info))
        .route("/api/v1/signup", web::post().to(handler::signup))
    })
    .bind(conf.server.address)?
    .run()
    .await
}