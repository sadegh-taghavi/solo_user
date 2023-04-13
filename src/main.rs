#[macro_use]
extern crate log;
use env_logger::Env;

mod config;
mod server;
mod auth;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Config file name
    #[arg(short, long, default_value_t = ("config.toml").to_string())]
    config: String,
}

fn main() {
    let args = Args::parse();

    let env = Env::default()
        .filter_or("LOG_LEVEL", "trace")
        .write_style_or("LOG_STYLE", "always");
    env_logger::init_from_env(env);

    let conf = config::init(args.config);
    info!("config loaded");
    
    let result = server::init(conf);
    if result.is_err() {
        panic!("error running server {}", result.as_ref().unwrap_err())
    }
    
}

