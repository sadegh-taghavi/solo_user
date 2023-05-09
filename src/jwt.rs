use std::future::{ready, Ready};

use actix_web::error::ErrorUnauthorized;
use actix_web::{dev::Payload, Error as ActixWebError};
use actix_web::{http, web, FromRequest, HttpRequest};
use jsonwebtoken::{decode, DecodingKey, Validation};

use crate::model::TokenClaims;

impl FromRequest for TokenClaims {
    type Error = ActixWebError;
    type Future = Ready<Result<Self, Self::Error>>;
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let data = req.app_data::<web::Data<crate::server::AppState>>().unwrap();

        // let token = req
            // .cookie("token")
            // .map(|c| c.value().to_string())
            // .or_else(|| {
                // req.headers()
                //     .get(http::header::AUTHORIZATION)
                //     .map(|h| h.to_str().unwrap().split_at(7).1.to_string());
            //  });

        let token = req.headers().get(http::header::AUTHORIZATION).map(|h| h.to_str().unwrap().split_at(7).1.to_string());
        if token.is_none() {
            return ready(Err(ErrorUnauthorized("provide token".to_string())));
        }

        let claims = match decode::<TokenClaims>(
            &token.unwrap(),
            &DecodingKey::from_secret(data.conf.jwt.secret.as_ref()),
            &Validation::default(),
        ) {
            Ok(c) => c.claims,
            Err(_) => {
                return ready(Err(ErrorUnauthorized("invalid token".to_string())));
            }
        };

        ready(Ok(claims))
    }
}