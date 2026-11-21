//! Accounts and device wallet ("carteira") for the RustDesk technician edition.
//!
//! A small HTTP service that runs beside hbbs, behind a TLS reverse proxy. A technician creates an
//! account in the app, and the wallet (devices grouped as "Company / Branch") follows the account to
//! every computer it signs in on. It never touches hbbs or its database.
//!
//! Environment: `CARTEIRA_BIND` (default `127.0.0.1:21114`), `CARTEIRA_DB` (default `carteira.sqlite3`).

use axum::{
    extract::{rejection::JsonRejection, ConnectInfo, Extension},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use flexi_logger::*;
use hbb_common::{
    log,
    serde_json::{self, json, Value},
    sodiumoxide::{crypto::hash::sha256, randombytes::randombytes},
    tokio, ResultType,
};
use serde_derive::{Deserialize, Serialize};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    SqlitePool,
};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    str::FromStr,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

const SESSION_IDLE_SECS: i64 = 30 * 24 * 3600;
const SESSION_TOUCH_SECS: i64 = 60;
const BCRYPT_COST: u32 = 10;
const SIGNUPS_PER_HOUR: usize = 5;
const LOGINS_PER_WINDOW: usize = 10;
const LOGIN_WINDOW_SECS: i64 = 15 * 60;
const MAX_DEVICES: usize = 2000;
const MAX_REVISION: i64 = 2_147_483_646;

struct App {
    db: SqlitePool,
    /// Checked when the e-mail has no account, so the response time does not reveal which e-mails exist.
    decoy_hash: String,
    limits: Mutex<HashMap<String, Vec<i64>>>,
}

type Shared = Extension<Arc<App>>;

#[derive(Deserialize)]
struct NewAccount {
    nome: String,
    email: String,
    senha: String,
}

#[derive(Deserialize)]
struct Login {
    login: String,
    senha: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Device {
    id: String,
    alias: String,
    group: String,
}

#[derive(Deserialize)]
struct Wallet {
    revisao: i64,
    dispositivos: Vec<Device>,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

fn error(status: StatusCode, code: &str, message: &str) -> Response {
    (status, Json(json!({ "message": message, "code": code }))).into_response()
}

fn no_store(body: Value) -> Response {
    ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response()
}

fn internal(err: impl std::fmt::Display) -> Response {
    log::error!("carteira: {err}");
    error(StatusCode::INTERNAL_SERVER_ERROR, "ERRO_INTERNO", "Erro interno")
}

fn token_hash(token: &str) -> String {
    base64::encode(sha256::hash(token.as_bytes()).0)
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

/// Behind the proxy every connection comes from loopback; the proxy puts the client in X-Forwarded-For.
fn client_ip(peer: Option<ConnectInfo<SocketAddr>>, headers: &HeaderMap) -> String {
    let peer = peer.map(|ConnectInfo(addr)| addr.ip());
    if peer.map_or(true, |ip| ip.is_loopback()) {
        if let Some(forwarded) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
        {
            return forwarded.trim().to_owned();
        }
    }
    peer.map(|ip| ip.to_string()).unwrap_or_default()
}

fn normalize_email(email: &str) -> Option<String> {
    let email = email.trim().to_lowercase();
    let (local, domain) = email.split_once('@')?;
    let valid = email.chars().count() <= 160
        && !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !email.chars().any(char::is_whitespace);
    valid.then_some(email)
}

impl App {
    async fn new(db: SqlitePool) -> ResultType<Arc<App>> {
        for ddl in [
            "create table if not exists contas (
                id integer primary key,
                nome text not null,
                email text not null unique,
                senha_hash text not null,
                criada_em integer not null)",
            "create table if not exists sessoes (
                token_hash text primary key,
                conta_id integer not null references contas(id) on delete cascade,
                expira_em integer not null,
                ultimo_uso_em integer not null,
                encerrada integer not null default 0)",
            "create index if not exists sessoes_conta on sessoes(conta_id)",
            "create table if not exists carteiras (
                conta_id integer primary key references contas(id) on delete cascade,
                revisao integer not null,
                dispositivos text not null)",
        ] {
            sqlx::query(ddl).execute(&db).await?;
        }
        let decoy_hash = tokio::task::spawn_blocking(|| bcrypt::hash("decoy", BCRYPT_COST)).await??;
        Ok(Arc::new(App {
            db,
            decoy_hash,
            limits: Mutex::new(HashMap::new()),
        }))
    }

    /// Counts an attempt; false once `max` attempts fall inside the window.
    fn allow(&self, key: String, max: usize, window: i64) -> bool {
        let now = now();
        let mut limits = self.limits.lock().unwrap();
        if limits.len() > 10_000 {
            limits.retain(|_, hits| hits.iter().any(|t| now - t < window));
        }
        let hits = limits.entry(key).or_default();
        hits.retain(|t| now - t < window);
        if hits.len() >= max {
            return false;
        }
        hits.push(now);
        true
    }

    fn forget(&self, key: &str) {
        self.limits.lock().unwrap().remove(key);
    }

    async fn open_session(&self, account: i64, name: &str) -> Result<Response, Response> {
        let token = base64::encode_config(randombytes(32), base64::URL_SAFE_NO_PAD);
        let now = now();
        sqlx::query(
            "insert into sessoes (token_hash, conta_id, expira_em, ultimo_uso_em) values (?, ?, ?, ?)",
        )
        .bind(token_hash(&token))
        .bind(account)
        .bind(now + SESSION_IDLE_SECS)
        .bind(now)
        .execute(&self.db)
        .await
        .map_err(internal)?;
        let expires = chrono::Utc::now() + chrono::Duration::seconds(SESSION_IDLE_SECS);
        Ok(no_store(json!({
            "token": token,
            "expiraEm": expires.to_rfc3339(),
            "usuario": { "nome": name },
        })))
    }

    /// The session's account. Use slides the expiry, at most once a minute.
    async fn account_of(&self, headers: &HeaderMap) -> Result<i64, Response> {
        let unauthorized = || error(StatusCode::UNAUTHORIZED, "SEM_SESSAO", "Faça login para continuar");
        let hash = token_hash(bearer(headers).ok_or_else(unauthorized)?);
        let row: Option<(i64, i64, i64, i64)> = sqlx::query_as(
            "select conta_id, expira_em, ultimo_uso_em, encerrada from sessoes where token_hash = ?",
        )
        .bind(&hash)
        .fetch_optional(&self.db)
        .await
        .map_err(internal)?;
        let now = now();
        match row {
            Some((account, expires, last_use, closed)) if closed == 0 && expires > now => {
                if now - last_use >= SESSION_TOUCH_SECS {
                    sqlx::query("update sessoes set ultimo_uso_em = ?, expira_em = ? where token_hash = ?")
                        .bind(now)
                        .bind(now + SESSION_IDLE_SECS)
                        .bind(&hash)
                        .execute(&self.db)
                        .await
                        .map_err(internal)?;
                }
                Ok(account)
            }
            _ => Err(unauthorized()),
        }
    }
}

fn bad_request() -> Response {
    error(
        StatusCode::BAD_REQUEST,
        "VALIDACAO",
        "Confira o nome, o e-mail e a senha (de 8 a 72 caracteres)",
    )
}

async fn create_account(
    Extension(app): Shared,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    body: Result<Json<NewAccount>, JsonRejection>,
) -> Response {
    // Before bcrypt: a refused signup costs nothing.
    if !app.allow(format!("contas:{}", client_ip(peer, &headers)), SIGNUPS_PER_HOUR, 3600) {
        return error(StatusCode::TOO_MANY_REQUESTS, "MUITAS_TENTATIVAS", "Muitas tentativas. Aguarde.");
    }
    let Ok(Json(body)) = body else { return bad_request() };
    let name = body.nome.trim().to_owned();
    let (Some(email), true, true) = (
        normalize_email(&body.email),
        (1..=120).contains(&name.chars().count()),
        (8..=72).contains(&body.senha.len()),
    ) else {
        return bad_request();
    };
    let password = body.senha;
    let hash = match tokio::task::spawn_blocking(move || bcrypt::hash(password, BCRYPT_COST)).await {
        Ok(Ok(hash)) => hash,
        Ok(Err(err)) => return internal(err),
        Err(err) => return internal(err),
    };
    let inserted = sqlx::query("insert or ignore into contas (nome, email, senha_hash, criada_em) values (?, ?, ?, ?)")
        .bind(&name)
        .bind(&email)
        .bind(hash)
        .bind(now())
        .execute(&app.db)
        .await;
    match inserted {
        Ok(done) if done.rows_affected() == 0 => {
            error(StatusCode::CONFLICT, "EMAIL_EM_USO", "Já existe uma conta com este e-mail")
        }
        Ok(done) => app
            .open_session(done.last_insert_rowid(), &name)
            .await
            .unwrap_or_else(|response| response),
        Err(err) => internal(err),
    }
}

async fn sign_in(
    Extension(app): Shared,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    body: Result<Json<Login>, JsonRejection>,
) -> Response {
    let Ok(Json(body)) = body else { return bad_request() };
    let email = body.login.trim().to_lowercase();
    let key = format!("entrar:{}:{email}", client_ip(peer, &headers));
    if !app.allow(key.clone(), LOGINS_PER_WINDOW, LOGIN_WINDOW_SECS) {
        return error(StatusCode::TOO_MANY_REQUESTS, "MUITAS_TENTATIVAS", "Muitas tentativas. Aguarde.");
    }
    let row: Option<(i64, String, String)> =
        match sqlx::query_as("select id, nome, senha_hash from contas where email = ?")
            .bind(&email)
            .fetch_optional(&app.db)
            .await
        {
            Ok(row) => row,
            Err(err) => return internal(err),
        };
    let hash = row.as_ref().map_or(app.decoy_hash.clone(), |(_, _, hash)| hash.clone());
    let password = body.senha;
    let matches = tokio::task::spawn_blocking(move || bcrypt::verify(password, &hash).unwrap_or(false))
        .await
        .unwrap_or(false);
    match row {
        Some((account, name, _)) if matches => {
            app.forget(&key);
            app.open_session(account, &name).await.unwrap_or_else(|response| response)
        }
        // The same answer for an unknown e-mail and a wrong password.
        _ => error(StatusCode::UNAUTHORIZED, "CREDENCIAL_INVALIDA", "E-mail ou senha incorretos"),
    }
}

async fn sign_out(Extension(app): Shared, headers: HeaderMap) -> Response {
    if let Some(token) = bearer(&headers) {
        if let Err(err) = sqlx::query("update sessoes set encerrada = 1 where token_hash = ?")
            .bind(token_hash(token))
            .execute(&app.db)
            .await
        {
            return internal(err);
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn read_wallet(Extension(app): Shared, headers: HeaderMap) -> Response {
    let account = match app.account_of(&headers).await {
        Ok(account) => account,
        Err(response) => return response,
    };
    let row: Option<(i64, String)> =
        match sqlx::query_as("select revisao, dispositivos from carteiras where conta_id = ?")
            .bind(account)
            .fetch_optional(&app.db)
            .await
        {
            Ok(row) => row,
            Err(err) => return internal(err),
        };
    let (revision, devices) = match row {
        Some((revision, devices)) => match serde_json::from_str::<Value>(&devices) {
            Ok(devices) => (revision, devices),
            Err(err) => return internal(err),
        },
        None => (0, json!([])),
    };
    no_store(json!({ "revisao": revision, "dispositivos": devices }))
}

fn valid_wallet(wallet: &Wallet) -> bool {
    let mut ids = HashSet::new();
    (0..=MAX_REVISION).contains(&wallet.revisao)
        && wallet.dispositivos.len() <= MAX_DEVICES
        && wallet.dispositivos.iter().all(|d| {
            let id = d.id.trim();
            !id.is_empty()
                && id.chars().count() <= 128
                && d.alias.chars().count() <= 120
                && d.group.chars().count() <= 120
                && ids.insert(id.to_owned())
        })
}

async fn write_wallet(
    Extension(app): Shared,
    headers: HeaderMap,
    body: Result<Json<Wallet>, JsonRejection>,
) -> Response {
    let account = match app.account_of(&headers).await {
        Ok(account) => account,
        Err(response) => return response,
    };
    let Ok(Json(wallet)) = body else {
        return error(StatusCode::BAD_REQUEST, "VALIDACAO", "Carteira inválida");
    };
    if !valid_wallet(&wallet) {
        return error(StatusCode::BAD_REQUEST, "VALIDACAO", "Carteira inválida");
    }
    let devices = match serde_json::to_string(&wallet.dispositivos) {
        Ok(devices) => devices,
        Err(err) => return internal(err),
    };
    let next = wallet.revisao + 1;
    // The revision is the lock: two computers writing over the same list, the second is refused
    // instead of erasing the first.
    let written = if wallet.revisao == 0 {
        sqlx::query("insert or ignore into carteiras (conta_id, revisao, dispositivos) values (?, ?, ?)")
            .bind(account)
            .bind(next)
            .bind(&devices)
            .execute(&app.db)
            .await
    } else {
        sqlx::query("update carteiras set revisao = ?, dispositivos = ? where conta_id = ? and revisao = ?")
            .bind(next)
            .bind(&devices)
            .bind(account)
            .bind(wallet.revisao)
            .execute(&app.db)
            .await
    };
    match written {
        Ok(done) if done.rows_affected() == 0 => error(
            StatusCode::CONFLICT,
            "CARTEIRA_DESATUALIZADA",
            "A carteira mudou em outro computador. Atualize a lista e tente novamente.",
        ),
        Ok(_) => no_store(json!({ "revisao": next, "dispositivos": wallet.dispositivos })),
        Err(err) => internal(err),
    }
}

fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/suporte/contas", post(create_account))
        .route("/suporte/entrar", post(sign_in))
        .route("/suporte/sair", post(sign_out))
        .route("/suporte/carteira", get(read_wallet).put(write_wallet))
        .layer(Extension(app))
}

async fn serve() -> ResultType<()> {
    let bind: SocketAddr = std::env::var("CARTEIRA_BIND")
        .unwrap_or_else(|_| "127.0.0.1:21114".to_owned())
        .parse()?;
    let path = std::env::var("CARTEIRA_DB").unwrap_or_else(|_| "carteira.sqlite3".to_owned());
    let options = SqliteConnectOptions::from_str(&format!("sqlite://{path}"))?.create_if_missing(true);
    let db = SqlitePoolOptions::new().max_connections(4).connect_with(options).await?;
    let app = App::new(db).await?;
    log::info!("carteira listening on {bind}, database {path}");
    axum::Server::bind(&bind)
        .serve(router(app).into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}

fn main() -> ResultType<()> {
    let _logger = Logger::try_with_env_or_str("info")?
        .log_to_stdout()
        .format(opt_format)
        .write_mode(WriteMode::Async)
        .start()?;
    hbb_common::sodiumoxide::init().map_err(|_| hbb_common::anyhow::anyhow!("sodiumoxide init failed"))?;
    tokio::runtime::Runtime::new()?.block_on(serve())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    struct Client(Router);

    impl Client {
        async fn new() -> Client {
            hbb_common::sodiumoxide::init().unwrap();
            let db = SqlitePoolOptions::new()
                .max_connections(1)
                .connect("sqlite::memory:")
                .await
                .unwrap();
            Client(router(App::new(db).await.unwrap()))
        }

        async fn call(&self, method: &str, uri: &str, token: Option<&str>, body: Value) -> (StatusCode, Value) {
            let mut request = Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json");
            if let Some(token) = token {
                request = request.header("authorization", format!("Bearer {token}"));
            }
            let response = self
                .0
                .clone()
                .oneshot(request.body(Body::from(body.to_string())).unwrap())
                .await
                .unwrap();
            let status = response.status();
            let bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
            (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
        }

        async fn create(&self, email: &str) -> String {
            let (status, body) = self
                .call("POST", "/suporte/contas", None, json!({"nome": "Ana", "email": email, "senha": "senha-boa-1"}))
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            body["token"].as_str().unwrap().to_owned()
        }
    }

    fn run<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }

    #[test]
    fn account_is_created_in_the_app_and_signs_in_again() {
        run(async {
            let client = Client::new().await;
            let (status, body) = client
                .call("POST", "/suporte/contas", None, json!({"nome": " Ana Ribeiro ", "email": " Ana@Teste.local ", "senha": "senha-boa-1"}))
                .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["usuario"]["nome"], "Ana Ribeiro");

            let (status, body) = client
                .call("POST", "/suporte/entrar", None, json!({"login": "ana@teste.local", "senha": "senha-boa-1"}))
                .await;
            assert_eq!(status, StatusCode::OK);
            let token = body["token"].as_str().unwrap();
            let (status, wallet) = client.call("GET", "/suporte/carteira", Some(token), Value::Null).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(wallet, json!({"revisao": 0, "dispositivos": []}));

            let (status, body) = client
                .call("POST", "/suporte/entrar", None, json!({"login": "ana@teste.local", "senha": "errada-123"}))
                .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(body["code"], "CREDENCIAL_INVALIDA");

            let (status, body) = client
                .call("POST", "/suporte/contas", None, json!({"nome": "Outra", "email": "ANA@teste.local", "senha": "senha-boa-2"}))
                .await;
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(body["code"], "EMAIL_EM_USO");

            let (status, _) = client
                .call("POST", "/suporte/contas", None, json!({"nome": "Bia", "email": "bia@teste.local", "senha": "curta"}))
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        });
    }

    #[test]
    fn wallet_follows_the_account_and_refuses_stale_writes() {
        run(async {
            let client = Client::new().await;
            let first = client.create("titular@teste.local").await;
            let (_, body) = client
                .call("POST", "/suporte/entrar", None, json!({"login": "titular@teste.local", "senha": "senha-boa-1"}))
                .await;
            let second = body["token"].as_str().unwrap().to_owned();
            let other = client.create("outra@teste.local").await;
            let devices = json!([{"id": "123456", "alias": "Caixa 1", "group": "Empresa / Filial"}]);

            let (status, saved) = client
                .call("PUT", "/suporte/carteira", Some(&first), json!({"revisao": 0, "dispositivos": devices}))
                .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(saved, json!({"revisao": 1, "dispositivos": devices}));
            assert_eq!(client.call("GET", "/suporte/carteira", Some(&second), Value::Null).await.1, saved);
            assert_eq!(
                client.call("GET", "/suporte/carteira", Some(&other), Value::Null).await.1,
                json!({"revisao": 0, "dispositivos": []})
            );
            let (status, _) = client
                .call("PUT", "/suporte/carteira", Some(&second), json!({"revisao": 0, "dispositivos": []}))
                .await;
            assert_eq!(status, StatusCode::CONFLICT);
        });
    }

    #[test]
    fn signing_out_ends_the_session() {
        run(async {
            let client = Client::new().await;
            let token = client.create("sai@teste.local").await;
            assert_eq!(client.call("GET", "/suporte/carteira", None, Value::Null).await.0, StatusCode::UNAUTHORIZED);
            assert_eq!(client.call("POST", "/suporte/sair", Some(&token), Value::Null).await.0, StatusCode::NO_CONTENT);
            assert_eq!(
                client.call("GET", "/suporte/carteira", Some(&token), Value::Null).await.0,
                StatusCode::UNAUTHORIZED
            );
        });
    }
}
