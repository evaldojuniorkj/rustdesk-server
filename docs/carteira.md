# Carteira: technician accounts and device wallet

`rustdesk-carteira` is a small HTTP service for the RustDesk technician edition
(`evaldojuniorkj/rustdesk`, `START_X_DEV_EDITION=technician`). A technician
creates an account in the app, and the wallet (devices grouped as
"Company / Branch") follows the account to every computer it signs in on.

It runs beside `hbbs` and `hbbr` and never touches them or their database.

## API

All bodies are JSON. Errors are `{ "message": "...", "code": "..." }`.

| Method | Path | Body | Answer |
|---|---|---|---|
| POST | `/suporte/contas` | `{nome, email, senha}` | 200 `{token, expiraEm, usuario: {nome}}`, 400, 409 `EMAIL_EM_USO`, 429 |
| POST | `/suporte/entrar` | `{login, senha}` (login is the e-mail) | 200 as above, 401 `CREDENCIAL_INVALIDA`, 429 |
| POST | `/suporte/sair` | (Bearer token) | 204 |
| GET | `/suporte/carteira` | (Bearer token) | 200 `{revisao, dispositivos: [{id, alias, group}], grupos}`, 401 |
| PUT | `/suporte/carteira` | `{revisao, dispositivos, grupos}` | 200 with `revisao + 1`, 409 `CARTEIRA_DESATUALIZADA` when `revisao` is stale |

- E-mail is trimmed and lowercased. Password: 8 to 72 bytes, stored with bcrypt.
- A session ends after 30 days without use; use slides the expiry. Only the
  SHA-256 of the token is stored.
- Signup: 5 per IP per hour. Sign-in: 10 attempts per IP and e-mail per 15
  minutes. The client IP comes from `X-Forwarded-For` when the connection is
  from loopback (the reverse proxy).
- `grupos` lists the networks and branches (`Network / Branch`) created with no
  device in them yet; it is optional, and a client that omits it saves an empty list.
- No e-mail confirmation and no password recovery yet.

## Configuration

| Variable | Default |
|---|---|
| `CARTEIRA_BIND` | `127.0.0.1:21114` |
| `CARTEIRA_DB` | `carteira.sqlite3` (SQLite, created on first start) |

## Deploy (test VPS `devstartx.vps-kinghost.net`)

Build for Linux x86_64 from a Mac (Docker Desktop):

```bash
docker run --rm --platform linux/amd64 -v "$PWD":/src -w /src \
  -v rustdesk-cargo-registry:/usr/local/cargo/registry \
  -e CARGO_TARGET_DIR=/src/target/linux-amd64 \
  -e CARGO_PROFILE_RELEASE_LTO=false -e CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
  rust:1-bookworm cargo build --release --bin rustdesk-carteira
```

Install on the VPS as `/usr/bin/rustdesk-carteira` with
`systemd/rustdesk-carteira.service`, and publish it with TLS through Caddy in
`/etc/caddy/conf.d/rustdesk-carteira.caddy`, imported by the main Caddyfile:

```
rustdesk.devstartx.vps-kinghost.net {
  encode zstd gzip
  reverse_proxy 127.0.0.1:21114
}
```

The app reaches it at `https://rustdesk.devstartx.vps-kinghost.net`.
