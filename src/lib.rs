use std::any::Any;
use std::collections::HashMap;
use std::env;
use std::ops::Add;

use actix_web::{get, HttpRequest, HttpResponse, post, Responder, web};
use actix_web::cookie::{Cookie, SameSite, time};
use actix_web::cookie::time::{Duration, OffsetDateTime};
use actix_web::Error;
use actix_web::FromRequest;
use actix_web::http::header::q;
use actix_web::web::Data;
use actix_web_httpauth::extractors::bearer::BearerAuth;
use actix_web_lab::__reexports::serde_json;
use actix_web_lab::__reexports::serde_json::Value;
use chrono::Utc;
use jsonwebtoken::{Algorithm, decode, DecodingKey, encode, EncodingKey, Header, Validation};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use sqlx::{Column, Pool, Postgres, Row};
use sqlx::postgres::PgRow;

use crate::serde_json::json;

pub struct EasyAuthState {
    pub pool: Pool<Postgres>,
    pub claim_fields: Vec<String>,
    pub unique_field: String,
}

const GET_ACCOUNT_DATA_WITH_UUID_SQL: &str = "select row_to_json(account) as data from account WHERE uuid = $1;";
const GET_ACCOUNT_DATA_WITH_EMAIL_SQL: &str = "SELECT * FROM account WHERE email = $1";
const IS_USERNAME_TAKEN_SQL: &str = "SELECT * FROM account where username = $1";
const REGISTER_ACCOUNT_RETURNING_DATA_SQL: &str = "INSERT INTO account (email, name, picture) VALUES ($1, $2, $3) RETURNING *;";

const ACCESS_TOKEN_LIFESPAN: i64 = 15 * 60;
const REFRESH_TOKEN_LIFESPAN: i64 = 7 * 24 * 60 * 60;


pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/oauth2")
        .service(refresh_access_token)
        .service(continue_with_google)
        .service(fetch_account_data)
        .service(is_username_taken)
        .service(logout)
    );
}

#[get("/is_username_taken")]
pub async fn is_username_taken(data: Data<EasyAuthState>, query: web::Query<IsUsernameTakenParams>) -> impl Responder {

    let username: String = query.username.clone();
    let pool = &data.pool;

    if sqlx::query("SELECT * FROM account where username = $1").bind(username).fetch_all(pool).await.unwrap().len() > 0 {
        return HttpResponse::Conflict().finish();
    }

    return HttpResponse::Ok().finish();
}


#[post("/logout")]
async fn logout() -> HttpResponse {

    let expired_cookie = Cookie::build("refresh_token", "N/A")
        .expires(OffsetDateTime::now_utc())
        .secure(true)
        .http_only(true)
        .path("/")
        .domain("localhost")
        .same_site(SameSite::None)
        .finish();

    return HttpResponse::Ok().cookie(expired_cookie).finish();
}



#[get("/fetch_account_data")]
 async fn fetch_account_data(data: Data<EasyAuthState>, auth: BearerAuth) -> HttpResponse {
    let access_token_info = fetch_access_token_information(auth.token().to_string());
    let pool = &data.pool;

    if let None = access_token_info {
        return HttpResponse::Unauthorized().finish();
    }

    let query = sqlx::query_as::<_, SerializableValue>(GET_ACCOUNT_DATA_WITH_UUID_SQL).bind(access_token_info.unwrap().uuid).fetch_one(pool).await;

    if query.is_err() {
        return HttpResponse::InternalServerError().json("this needs a better error, please nag the developer")
    }

    return HttpResponse::Ok().json(query.unwrap())
}

fn log(message: &str) {
    println!("[EasyAuth] [{}]:  {}", Utc::now().format("%Y-%m-%d %H:%M:%S") , message);
}

#[get("/refresh_access_token")]
 async fn refresh_access_token(request: HttpRequest) -> HttpResponse {
    if request.cookie("refresh_token").is_none() {
            return HttpResponse::BadRequest().json("Refresh token not provided");
    }



    let decoded_refresh_token_result = decode::<EasyAuthJWT>(&request.cookie("refresh_token").unwrap().value(), &DecodingKey::from_secret(env::var("EASY_AUTH_REFRESH_TOKEN_SECRET").unwrap().as_ref()), &Validation::new(Algorithm::HS512));

    if decoded_refresh_token_result.is_err() {
        return HttpResponse::Unauthorized().json("Failed to refresh token")
    }


    let access_token = generate_access_token(&decoded_refresh_token_result.unwrap().claims.uuid).unwrap();

    return HttpResponse::Ok().json(access_token);
    }


#[post("/google")]
async fn continue_with_google(data: Data<EasyAuthState>, body: web::Json<GoogleContinueRequest>) -> impl Responder {
    let identity_token_info = fetch_identity_token_info(body.access_token.clone()).await;


    if let Err(_) = identity_token_info {
        return HttpResponse::Unauthorized().json("Invalid Token");
    }




    let pool = &data.pool;
    let email = &identity_token_info.as_ref().unwrap().email;
    let name = &identity_token_info.as_ref().unwrap().name;
    let picture = &identity_token_info.as_ref().unwrap().picture;


    let account_data_result =  register_with_google(pool, email, name, picture).await;

    if account_data_result.is_err() {
        return HttpResponse::InternalServerError().json("you should tell the developer to make better errors");
    }

    let account_uuid = &account_data_result.unwrap().uuid;




    let refresh_token = generate_refresh_token(account_uuid).unwrap();
    let access_token = generate_access_token(account_uuid).unwrap();

    HttpResponse::Ok().cookie(refresh_token).json(access_token)
}


async fn login_with_google(pool: &Pool<Postgres>, email: &String) -> Result<Account, GoogleFlowError> {
    let query = sqlx::query_as::<_, Account>(GET_ACCOUNT_DATA_WITH_EMAIL_SQL).bind(email).fetch_one(pool).await;
    log("Logging in with Google");

    // TODO match more errors for more descriptive errors
    if query.is_err() {
        return Err(GoogleFlowError::VagueError)
    }

    return Ok(query.unwrap())
}

async fn register_with_google(pool: &Pool<Postgres>, email: &String, name: &String, picture: &String) -> Result<Account, GoogleFlowError> {
    let query  = sqlx::query_as::<_, Account>(REGISTER_ACCOUNT_RETURNING_DATA_SQL).bind(email).bind(name).bind(picture).fetch_one(pool).await;
    log("Registering with Google");


    if query.is_ok() {
        log("Google registration complete");
        return Ok(query.unwrap())
    }


    return match query.err().unwrap() {
        sqlx::Error::Database(database_error) => {

            // If email is taken, login.
            if database_error.constraint() == Some("account_email_key") {
                log("Account exists - logging in");
                return login_with_google(pool, email).await
            }

            log(format!("Database error during Google registration / {:?}", database_error.message()).as_str());
            Err(GoogleFlowError::VagueError)
        },
        _ => Err(GoogleFlowError::VagueError)
    }

}







pub async fn fetch_identity_token_info(token: String) -> Result<GoogleClaims, String> {
    let client = reqwest::Client::new();

    return match client.get(format!("https://www.googleapis.com/oauth2/v3/userinfo?access_token={token}")).send().await {
        Ok(response) => {

            match response.status() == StatusCode::OK {
                true => {
                    Ok(response.json::<GoogleClaims>().await.unwrap())
                }
                false => Err("Invalid Token".to_string())
            }
        }
        Err(error) => {
            return Err(error.to_string());
        }
    };
}

pub fn generate_access_token(uuid: &String) -> Result<String, jsonwebtoken::errors::Error> {

    let mut claim: EasyAuthJWT = EasyAuthJWT {
        uuid: uuid.to_string(),
        exp: (Utc::now().timestamp() + REFRESH_TOKEN_LIFESPAN),
    };



    let token = encode(&Header::default(), &claim, &EncodingKey::from_secret(env::var("EASY_AUTH_ACCESS_TOKEN_SECRET").unwrap().as_ref()));

    if let Err(error) = token {
        return Err(error);
    }

    return token;
}

// Generates the Refresh JWT and the encapsulating cookie
pub fn generate_refresh_token(uuid: &String) -> Result<Cookie<'static>, jsonwebtoken::errors::Error> {

    let mut claim: EasyAuthJWT = EasyAuthJWT {
        uuid: uuid.to_string(),
        exp: (Utc::now().timestamp() + REFRESH_TOKEN_LIFESPAN),
    };



    let token = encode(&Header::new(Algorithm::HS512), &claim, &EncodingKey::from_secret(env::var("EASY_AUTH_REFRESH_TOKEN_SECRET").unwrap().as_ref()));

    if let Err(error) = token {
        return Err(error);
    }

    Ok(Cookie::build("refresh_token", token.unwrap())
        .expires(OffsetDateTime::now_utc().add(Duration::seconds(REFRESH_TOKEN_LIFESPAN)))
        .secure(true)
        .http_only(true)
        .path("/")
        .domain("localhost")
        .same_site(SameSite::None)
        .finish())
}

pub fn fetch_access_token_information(token: String) -> Option<EasyAuthJWT> {
    match decode::<EasyAuthJWT>(&token, &DecodingKey::from_secret(env::var("EASY_AUTH_ACCESS_TOKEN_SECRET").unwrap().as_ref()), &Validation::default()) {
        Ok(data) => Some(data.claims),
        Err(error) => {
            println!("Failed to fetch access token info, error {error:}");
            None
        }
    }
}


// START OF TYPES



#[derive(Deserialize, Serialize, Debug, sqlx::FromRow, sqlx::Decode)]
struct  SerializableValue(serde_json::Value);

#[derive(Clone, Debug)]
enum GoogleFlowError {
    VagueError
}

#[derive(Deserialize)]
pub struct GoogleContinueRequest {
    access_token: String,
    username: Option<String>,
}


// THE JWT used for authentication
#[derive(Deserialize, Serialize, Debug)]
pub struct EasyAuthJWT {
    pub uuid: String,
    exp: i64,
}

#[derive(Deserialize)]
pub struct IsUsernameTakenParams {
    username: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct GoogleClaims {
    pub email: String,
    name: String,
    picture: String,
}

#[derive(Serialize, Deserialize, sqlx::FromRow)]
struct Account {
    uuid: String,
}

// END OF TYPES

