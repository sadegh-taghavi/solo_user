use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
   pub server: Server,
}

#[derive(Debug, Deserialize)]
pub struct Server {
   pub address: String,
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