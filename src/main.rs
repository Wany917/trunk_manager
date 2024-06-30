use actix_cors::Cors;
use actix_session::{Session, SessionMiddleware, storage::RedisSessionStore};
use actix_web::{web, App, HttpServer, HttpResponse, Responder, post, get, Error};
use actix_web::cookie::{Key, SameSite};
use actix_web::middleware::Logger;
use bcrypt::{hash, verify, DEFAULT_COST};
use rand::{distributions::Alphanumeric, Rng};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use env_logger;

#[derive(Serialize, Deserialize, Clone)]
struct PasswordVault {
    master_key_hash: String,
    passwords: Vec<PasswordRecord>,
}

#[derive(Serialize, Deserialize, Clone)]
struct PasswordRecord {
    site: String,
    #[serde(default)]
    password: String,
}

struct AppState {
    vault: Mutex<PasswordVault>,
}

fn generate_password(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

fn validate_url(url: &str) -> bool {
    let url_regex = Regex::new(r"^(https?://)?([\w\.]+)\.([a-z]{2,6}\.?)(/[^\s]*)?$").unwrap();
    url_regex.is_match(url)
}

#[derive(Deserialize)]
struct MasterKey {
    master_key: String,
}

#[post("/initialize")]
async fn initialize(data: web::Data<AppState>, key: web::Json<MasterKey>) -> Result<HttpResponse, Error> {
    let mut vault = data.vault.lock().unwrap();
    if vault.master_key_hash.is_empty() {
        let master_key_hash = hash(&key.master_key, DEFAULT_COST).unwrap();
        vault.master_key_hash = master_key_hash;
        Ok(HttpResponse::Ok().json("Master key initialized"))
    } else {
        Ok(HttpResponse::BadRequest().body("Master key already initialized"))
    }
}

#[post("/login")]
async fn login(data: web::Data<AppState>, session: Session, key: web::Json<MasterKey>) -> Result<HttpResponse, Error> {
    let vault = data.vault.lock().unwrap();
    if verify(&key.master_key, &vault.master_key_hash).unwrap() {
        session.insert("authenticated", true)?;
        session.renew(); // Regenerate session ID to prevent fixation attacks
        println!("User logged in successfully");
        Ok(HttpResponse::Ok().json("Login successful"))
    } else {
        println!("Invalid master key");
        Ok(HttpResponse::Unauthorized().body("Invalid master key"))
    }
}

#[post("/add_password")]
async fn add_password(session: Session, data: web::Data<AppState>, info: web::Json<PasswordRecord>) -> impl Responder {
    match session.get::<bool>("authenticated") {
        Ok(Some(true)) => {
            println!("Session authenticated");
            let mut vault = data.vault.lock().unwrap();
            if validate_url(&info.site) {
                let new_password = generate_password(12);
                let hashed_password = hash(&new_password, DEFAULT_COST).unwrap();
                vault.passwords.push(PasswordRecord {
                    site: info.site.clone(),
                    password: hashed_password,
                });
                HttpResponse::Ok().json("Password added")
            } else {
                HttpResponse::BadRequest().body("Invalid URL")
            }
        },
        Ok(Some(false)) | Ok(None) => {
            println!("Session not authenticated");
            HttpResponse::Unauthorized().body("Not authenticated")
        },
        Err(e) => {
            println!("Error getting session: {:?}", e);
            HttpResponse::Unauthorized().body("Not authenticated")
        }
    }
}

#[get("/show_passwords")]
async fn show_passwords(session: Session, data: web::Data<AppState>) -> impl Responder {
    match session.get::<bool>("authenticated") {
        Ok(Some(true)) => {
            println!("Session authenticated");
            let vault = data.vault.lock().unwrap();
            HttpResponse::Ok().json(&vault.passwords)
        },
        Ok(Some(false)) | Ok(None) => {
            println!("Session not authenticated");
            HttpResponse::Unauthorized().body("Not authenticated")
        },
        Err(e) => {
            println!("Error getting session: {:?}", e);
            HttpResponse::Unauthorized().body("Not authenticated")
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init(); // Initialize logger
    let vault = PasswordVault {
        master_key_hash: String::new(),
        passwords: vec![],
    };

    let app_data = web::Data::new(AppState {
        vault: Mutex::new(vault),
    });

    let secret_key = Key::generate(); // Generate a random key for signing/encrypting cookies
    let redis_store = RedisSessionStore::new("redis://127.0.0.1:6379").await.map_err(|err| {
        eprintln!("Failed to connect to Redis: {}", err);
        std::io::Error::new(std::io::ErrorKind::Other, "Failed to connect to Redis")
    })?;

    HttpServer::new(move || {
        let cors = Cors::permissive();
        App::new()
            .wrap(Logger::default()) // Enable logging
            .app_data(app_data.clone())
            .wrap(cors)
            .wrap(SessionMiddleware::builder(redis_store.clone(), secret_key.clone())
                .cookie_secure(false) // Set to true in production
                .cookie_http_only(true)
                .cookie_same_site(SameSite::Lax)
                .build())
            .service(initialize)
            .service(login)
            .service(add_password)
            .service(show_passwords)
    })
    .bind("0.0.0.0:8080")?  // Listen on all network interfaces
    .run()
    .await
}
