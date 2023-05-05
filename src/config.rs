use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
   pub server: Server,
   pub db: DB,
   pub jwt: JWT,
   pub oauth: OAuth,
}

#[derive(Debug, Deserialize,Clone)]
pub struct Server {
   pub address: String,
}

#[derive(Debug, Deserialize,Clone)]
pub struct DB {
   pub data_source: String,
}

#[derive(Debug, Deserialize,Clone)]
pub struct JWT {
   pub secret: String,
   pub expire: i64,
   pub maxage: i64,
}

#[derive(Debug, Deserialize,Clone)]
pub struct OAuth {
   pub verify_url: String,
   pub google_client_id: String,
   pub google_client_secret: String,
   pub auth_url: String,
   pub token_url: String,
   pub revokation_url: String,
   pub redirect_url: String,
   pub userinfo_url: String,
}

pub fn init(file: String) -> Config {

    let result = std::fs::read_to_string(file);
    if result.is_err() {
        panic!("cannnot load config file: {}", result.as_ref().unwrap_err()  );
    }
    let result = toml::from_str(&result.as_ref().unwrap());
    if result.is_err() {
        panic!("cannnot parse config file: {}", result.as_ref().unwrap_err()  );
    }
    result.unwrap()
}