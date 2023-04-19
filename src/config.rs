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
   pub datasource: String,
}

#[derive(Debug, Deserialize,Clone)]
pub struct JWT {
   pub secret: String,
   pub expire: i32,
   pub maxage: i32,
}

#[derive(Debug, Deserialize,Clone)]
pub struct OAuth {
   pub googleclientid: String,
   pub googleclientsecret: String,
   pub authurl: String,
   pub tokenurl: String,
   pub revokationurl: String,
   pub redirecturl: String,
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