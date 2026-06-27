# Sentri


An API gateway for Large Language Models with semantic caching, a multi-layer guardrails pipeline, API key authentication, circuit breaking, and per-key rate limiting. Built to reduce LLM API costs, enforce safety policies, and protect your infrastructure before requests ever reach the model.

---

## Table of Contents

- [The Problem](#the-problem)
- [Architecture](#architecture)
- [Features](#features)
  - [API Key Authentication](#api-key-authentication)
  - [Semantic Caching (L1 + L2)](#semantic-caching-l1--l2)
  - [Guardrails Pipeline](#guardrails-pipeline)
  - [Circuit Breaker & Provider Fallback](#circuit-breaker--provider-fallback)
  - [Rate Limiting](#rate-limiting)
  - [Observability](#observability)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [First-Time Setup & Bootstrap](#first-time-setup--bootstrap)
- [Repurposing Sentri for Any Domain](#repurposing-sentri-for-any-domain)
- [API Reference](#api-reference)
  - [POST /v1/chat](#post-v1chat)
  - [GET /health](#get-health)
  - [GET /metrics](#get-metrics)
  - [POST /admin/keys](#post-adminkeys)
  - [GET /admin/keys](#get-adminkeys)
  - [GET /admin/keys/{key_id}](#get-adminkeyskey_id)
  - [DELETE /admin/keys/{key_id}](#delete-adminkeyskey_id)
  - [POST /admin/keys/{key_id}/rotate](#post-adminkeyskey_idrotate)
- [Environment Variables](#environment-variables)
- [Design Decisions](#design-decisions)

---

## The Problem

Every LLM API call costs money and takes 1–3 seconds. When multiple users ask semantically identical questions — *"what is BFS"*, *"explain breadth first search"*, *"how does level order traversal work"* — exact-match caching misses all of them. Additionally, production LLM applications need:

- **Safety layers** to prevent prompt injection, PII leakage, and off-topic abuse
- **Authentication** so only authorised callers can consume your LLM quota
- **Resilience** so a single provider outage doesn't take down your application
- **Rate limiting** to prevent quota exhaustion by a single caller

This gateway sits between your application and the LLM, solving all of these at once.

---

## Architecture

```
Incoming Request
       │
       ▼
┌─────────────────────┐
│  Rate Limiter       │ ──── 429 ──► "Rate limit exceeded"
│  (Redis sliding     │
│   window, per-key)  │
└────────┬────────────┘
         │ within limit
         ▼
┌─────────────────────┐
│  Auth (X-API-Key)   │ ──── 401 ──► "Missing or invalid API key"
│  SHA-256 lookup     │ ──── 403 ──► "Admin role required"
│  in Redis           │
└────────┬────────────┘
         │ authenticated
         ▼
┌─────────────────────────────────┐
│        Input Guardrails         │
│                                 │
│  0. Size Check  (32KB limit)    │ ──── BLOCK (400) ──► "Request too large"
│  1. Injection Check  (~0ms)     │ ──── BLOCK (400) ──► "Prompt injection detected"
│  2. Domain Policy    (~30ms)    │ ──── BLOCK (400) ──► "Off-topic request"
│  3. PII Scrubbing    (~20ms)    │ ──── scrub & continue
└────────┬────────────────────────┘
         │ passed
         ▼
┌─────────────────────┐
│   L1 Exact Cache    │ ──── HIT ──► return in ~1ms
│   (Redis MD5 hash)  │
└────────┬────────────┘
         │ miss
         ▼
┌─────────────────────┐
│  L2 Semantic Cache  │ ──── HIT ──► return in ~10ms
│  (Redis Vector KNN) │
│  + Stampede Guard   │
└────────┬────────────┘
         │ miss (lock acquired)
         ▼
┌─────────────────────┐
│  Circuit Breaker    │
│  Provider Factory   │ ──── tries groq → fallback chain
│  (groq / openai)    │ ──── ~800–1500ms
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Output Guardrails  │
│  PII scrub on resp  │
└────────┬────────────┘
         │
         ▼
   Cache Store + Release Stampede Lock + Return
```

---

## Features

### API Key Authentication

Every request to `/v1/chat` and all `/metrics` endpoints must carry a valid `X-API-Key` header. Admin-only endpoints additionally require a key with `role=admin`.

**How it works:**

- Keys are generated with `secrets.token_hex(32)`, prefixed `sentri_`, giving 256 bits of entropy
- Only the **SHA-256 hash** is stored in Redis — the plaintext is returned once at creation and never stored
- Each key carries: `name`, `role` (user/admin), `rate_limit`, `created_at`, `last_used_at`, `usage_count`, `is_active`
- Revocation is **immediate** — soft-delete sets `is_active=0`; the record is kept for audit
- **Rotation** atomically revokes the old key and issues a replacement with the same name/role/rate_limit

**Roles:**

| Role | Access |
|---|---|
| `user` | `POST /v1/chat` only |
| `admin` | All endpoints including `/admin/keys` and `/metrics` |

**Error responses:**

```json
// Missing header
{ "error": "Missing API key", "hint": "Supply your key in the X-API-Key request header." }

// Invalid or revoked key
{ "error": "Invalid or revoked API key" }

// Wrong role
{ "error": "Admin role required for this endpoint" }
```

---

### Semantic Caching (L1 + L2)

**L1 — Exact Cache** — MD5 hash lookup in Redis. The same query twice returns in ~1ms with zero compute.

**L2 — Semantic Cache** — Converts queries to 384-dimensional embeddings using `sentence-transformers/all-MiniLM-L6-v2`. Uses Redis Stack's `FT.SEARCH` with KNN vector similarity to find semantically equivalent past queries. Configurable cosine similarity threshold (default: `0.85`).

**Stampede Guard** — When 50 concurrent requests miss the cache for the same query simultaneously, only one wins a distributed lock and makes the LLM call. The other 49 wait on an `asyncio.Event` and read the cache once it's populated. This prevents 49 redundant LLM calls under burst load.

On a typical Q&A workload, cache hit rates of 60–70% are observed after warmup, directly reducing LLM API costs by the same proportion.

---

### Guardrails Pipeline

A **plugin-style registry** — add a new guardrail by creating a class that extends `InputGuardrail` and calling `pipeline.register()` at startup. No edits to `pipeline.py` needed.

Four layers ordered by computational cost (cheapest first):

**Layer 0 — Request Size Limit (~0ms)**
Hard 32KB limit checked before any other processing. Prevents resource exhaustion from maliciously large payloads.

**Layer 1 — Prompt Injection Detection (~0ms)**
Two-pass detector:
- **Pass A**: Pattern-based matching against 20+ compiled regexes covering 5 attack categories: instruction override, role hijacking, system prompt extraction, jailbreak attempts, and delimiter injection
- **Pass B**: Normalisation pass — NFKC Unicode normalisation, homoglyph replacement (Cyrillic lookalikes → ASCII), base64 fragment decoding — then re-runs the same patterns. Catches evasion attempts that bypass Pass A
- Multilingual patterns cover French, Spanish, and German override attempts

**Layer 2 — Domain Policy Validator (~30ms)**
Semantic topic enforcement built on the same embedding infrastructure as the cache. At startup, encodes the configured `DOMAIN_TOPICS` list as reference embeddings, then computes cosine similarity between the incoming query and each topic. Blocks requests below `DOMAIN_THRESHOLD`. Unlike keyword filters, this understands intent — *"reverse a linked list"* matches the "linked lists" topic even without exact keyword matches. Fully configurable: set `DOMAIN_TOPICS` and `DEFAULT_SYSTEM_PROMPT` in `.env` to repurpose Sentri for any domain without touching code.

**Layer 3 — PII Detection & Scrubbing (~20ms)**
Microsoft Presidio-powered detection and anonymisation for 8 entity types: email, phone, credit card, IBAN, IP address, person name, location, and crypto addresses. Runs **asynchronously** in a thread pool (`asyncio.to_thread`) so it never blocks the event loop. PII is replaced with labelled tokens (`<EMAIL>`, `<PHONE>`) before the query reaches the LLM — ensuring no user data is sent to third-party APIs.

Output guardrails run the same PII scrubber on LLM responses before returning to the caller.

---

### Circuit Breaker & Provider Fallback

Three-state machine per provider: **CLOSED** (normal) → **OPEN** (failing) → **HALF_OPEN** (testing recovery).

```
CLOSED ──(N failures)──► OPEN ──(timeout elapsed)──► HALF_OPEN
  ▲                                                        │
  └──────────────(success)────────────────────────────────┘
                    │
              (failure) → OPEN
```

- Opens after `CIRCUIT_FAILURE_THRESHOLD` consecutive failures (default: 5)
- Stays open for `CIRCUIT_RECOVERY_TIMEOUT` seconds (default: 60s)
- In HALF_OPEN, allows up to 2 test calls; one success closes the circuit, one failure re-opens it

**Fallback chain** — if the requested provider's circuit is open, `call_with_fallback()` walks a configurable priority list (`groq → openai`). If all providers are exhausted, returns HTTP 503. Circuit state for each provider is included in the `/metrics` response.

---

### Rate Limiting

Redis sliding-window rate limiter applied to `/v1/chat`.

**Per-key limits** — each API key has its own `rate_limit` field (requests per minute). An internal service key can be given 1000 req/min; a test key can be limited to 10. The limit is enforced by bucking on `key_id` in Redis.

**Fallback to IP** — for any path not requiring auth (e.g. `/health`), rate limiting falls back to the caller's IP address.

**Headers returned on every response:**

```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 47
X-RateLimit-Reset: 1719000060
```

**When exceeded:**

```json
{
  "error": "Rate limit exceeded",
  "limit": 60,
  "window_seconds": 60,
  "retry_after": 60
}
```

The limiter **fails open** — if Redis is unreachable, requests are allowed through rather than blocking legitimate traffic.

---

### Observability

**`GET /metrics`** (admin only) — live JSON summary:

```json
{
  "total_requests": 248,
  "cache_hit_rate_percent": 64.5,
  "cache_hits": { "exact": 89, "semantic": 71 },
  "cache_misses": 88,
  "blocked": {
    "injection_attempts": 3,
    "off_topic": 7,
    "pii_scrubbed": 2,
    "oversized_requests": 1
  },
  "rate_limited": 4,
  "tokens_used": 31240,
  "latency": {
    "avg_ms": 213.4,
    "p99_ms": 1847.2
  },
  "circuit_breakers": {
    "groq": {
      "state": "closed",
      "failure_count": 0,
      "last_failure_ago_s": null
    }
  }
}
```

**Metrics persistence** — the store flushes to Redis every 10 requests and restores on startup. A process restart doesn't wipe your stats.

**p99 latency** — in addition to average, the store tracks the 99th-percentile latency across the last 1000 requests.

---

## Tech Stack

| Layer | Technology |
|---|---|
| API Framework | FastAPI + Uvicorn (async) |
| Cache Storage | Redis Stack (RedisSearch + vector index) |
| Embeddings | `sentence-transformers/all-MiniLM-L6-v2` |
| PII Detection | Microsoft Presidio |
| LLM Providers | Groq (Llama 3.1), OpenAI |
| Auth | SHA-256 hashed API keys in Redis |
| Validation | Pydantic v2 |
| Config | pydantic-settings + dotenv |
| Containerisation | Docker + Docker Compose |

---

## Project Structure

```
sentri/
├── app/
│   ├── api/
│   │   ├── routes.py            # /v1/chat, /health, /metrics endpoints
│   │   └── admin_routes.py      # /admin/keys CRUD endpoints
│   ├── auth/
│   │   ├── key_manager.py       # Redis-backed API key store (hashed)
│   │   └── dependencies.py      # require_auth / require_admin FastAPI deps
│   ├── cache/
│   │   └── semantic_cache.py    # L1 exact + L2 semantic cache + stampede guard
│   ├── core/
│   │   ├── config.py            # pydantic-settings config (all env vars)
│   │   └── metrics.py           # in-memory + Redis-persisted metrics store
│   ├── guardrails/
│   │   ├── pipeline.py          # plugin registry + async orchestration
│   │   ├── injection_detector.py # two-pass regex + normalisation detector
│   │   ├── domain_policy.py     # embedding-based topic validator
│   │   └── pii_detector.py      # Presidio PII scrubber
│   ├── middleware/
│   │   └── rate_limiter.py      # Redis sliding-window rate limiter
│   ├── providers/
│   │   ├── base.py              # abstract BaseLLMProvider + request/response models
│   │   ├── circuit_breaker.py   # three-state circuit breaker
│   │   ├── factory.py           # provider registry + call_with_fallback()
│   │   └── groq_provider.py     # Groq implementation
│   └── main.py                  # FastAPI app, middleware, lifespan hooks
├── main.py                      # uvicorn entrypoint
├── docker-compose.yml           # Redis Stack
├── requirements.txt
└── .env.example
```

---

## Getting Started

### Prerequisites

- Python 3.10+
- Docker + Docker Compose
- Groq API key (free at [console.groq.com](https://console.groq.com))

### Setup

**1. Clone the repo**

```bash
git clone https://github.com/agvatsal1312/sentri.git
cd sentri
```

**2. Create a virtual environment**

```bash
python -m venv venv
source venv/bin/activate        # macOS/Linux
venv\Scripts\activate           # Windows
```

**3. Install dependencies**

```bash
pip install -r requirements.txt
```

**4. Configure environment**

```bash
cp .env.example .env
```

Open `.env` and fill in the required values (see [Environment Variables](#environment-variables) below).

**5. Generate your admin bootstrap key**

```bash
python -c "import secrets; print('sentri_' + secrets.token_hex(32))"
```

Copy the output into `.env` as `GATEWAY_ADMIN_KEY`. This key is registered on first startup and used to create all other keys via the API.

**6. Start Redis Stack**

```bash
docker-compose up -d
```

This starts Redis Stack (includes RedisSearch for vector indexing) and exposes:
- `6379` — Redis
- `8001` — RedisInsight web UI (optional, for debugging)

**7. Run the server**

```bash
python main.py
```

Server starts at `http://localhost:8000`. Interactive API docs at `http://localhost:8000/docs`.

---

## First-Time Setup & Bootstrap

On startup the gateway checks for `GATEWAY_ADMIN_KEY` in your environment. If set, it registers that key as an admin bootstrap key (idempotent — safe to restart). This is your entry point into the key management API.

**Step 1 — Verify your admin key works**

```bash
curl http://localhost:8000/metrics \
  -H "X-API-Key: sentri_your_admin_key_here"
```

**Step 2 — Create a user key for your application**

```bash
curl -X POST http://localhost:8000/admin/keys \
  -H "X-API-Key: sentri_your_admin_key_here" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-app",
    "role": "user",
    "rate_limit": 60
  }'
```

Response (save the `api_key` — it is shown **once only**):

```json
{
  "api_key": "sentri_abc123...",
  "key_id": "key_f3a9c1",
  "name": "my-app",
  "role": "user",
  "rate_limit": 60,
  "created_at": "2025-06-22T10:00:00+00:00",
  "message": "Store this key securely — it will not be shown again."
}
```

**Step 3 — Make your first chat request**

```bash
curl -X POST http://localhost:8000/v1/chat \
  -H "X-API-Key: sentri_abc123..." \
  -H "Content-Type: application/json" \
  -d '{
    "message": "explain dijkstra'\''s algorithm",
    "provider": "groq"
  }'
```

---

## Repurposing Sentri for Any Domain

Sentri is not tied to DSA. Three `.env` variables control the domain entirely — no code changes needed.

- **`DEFAULT_SYSTEM_PROMPT`** — the role instruction the LLM receives on every request
- **`DOMAIN_TOPICS`** — comma-separated list of topics the gateway will allow through
- **`DOMAIN_THRESHOLD`** — how strictly to enforce it (default `0.30`, range `0.0`–`1.0`)

| Use case | `DEFAULT_SYSTEM_PROMPT` | `DOMAIN_TOPICS` |
|---|---|---|
| DSA tutor *(default)* | `You are a helpful DSA tutor.` | *(built-in DSA list)* |
| Customer support | `You are a support agent for Acme Corp.` | `orders,refunds,shipping,billing,account` |
| Python tutor | `You are a Python programming tutor.` | `python basics,functions,classes,loops,debugging` |
| Medical info | `You are a medical information assistant.` | `cardiology,oncology,pharmacology,symptoms` |
| Open gateway | *(any prompt)* | *(set `ENABLE_DOMAIN_POLICY=false`)* |

After editing `.env`, restart the server — Sentri picks up the new config on startup.

---

## API Reference

### `POST /v1/chat`

Send a message through the gateway. Requires a valid API key (`user` or `admin` role).

**Headers**

```
X-API-Key: sentri_your_key_here
Content-Type: application/json
```

**Request body**

```json
{
  "message": "explain dijkstra's algorithm",
  "provider": "groq",
  "system_prompt": "You are a helpful DSA tutor.",
  "temperature": 0.7,
  "max_tokens": 1024
}
```

| Field | Type | Default | Description |
|---|---|---|---|
| `message` | string | required | The user query |
| `provider` | string | `"groq"` | LLM provider to use (`"groq"`, `"openai"`) |
| `system_prompt` | string | *value of `DEFAULT_SYSTEM_PROMPT` in `.env`* | Overrides the system prompt for this request only |
| `temperature` | float | `0.7` | Sampling temperature |
| `max_tokens` | int | `1024` | Max tokens in the response |

**Response — LLM call (cache miss)**

```json
{
  "response": "Dijkstra's algorithm is a graph traversal...",
  "cache_hit": false,
  "cache_type": null,
  "similarity": null,
  "provider": "groq",
  "tokens_used": 312,
  "pii_detected": [],
  "latency_ms": 876.4
}
```

**Response — Exact cache hit**

```json
{
  "response": "Dijkstra's algorithm is a graph traversal...",
  "cache_hit": true,
  "cache_type": "exact",
  "similarity": 1.0,
  "provider": null,
  "tokens_used": null,
  "pii_detected": [],
  "latency_ms": 1.2
}
```

**Response — Semantic cache hit**

```json
{
  "response": "Dijkstra's algorithm is a graph traversal...",
  "cache_hit": true,
  "cache_type": "semantic",
  "similarity": 0.9119,
  "provider": null,
  "tokens_used": null,
  "pii_detected": [],
  "latency_ms": 14.2
}
```

**Response — Blocked by guardrails (400)**

```json
{
  "error": "Request blocked by guardrails",
  "reason": "Prompt injection detected: instruction_override — matched 'ignore all previous instructions'"
}
```

**Response — All providers unavailable (503)**

```json
{
  "error": "All LLM providers are unavailable. Please retry later."
}
```

---

### `GET /health`

Public endpoint — no authentication required. Returns immediately; suitable for load balancer probes.

```json
{ "status": "ok" }
```

---

### `GET /metrics`

Returns live gateway statistics. Requires an **admin** key.

```json
{
  "total_requests": 248,
  "cache_hit_rate_percent": 64.5,
  "cache_hits": {
    "exact": 89,
    "semantic": 71
  },
  "cache_misses": 88,
  "blocked": {
    "injection_attempts": 3,
    "off_topic": 7,
    "pii_scrubbed": 2,
    "oversized_requests": 1
  },
  "rate_limited": 4,
  "tokens_used": 31240,
  "latency": {
    "avg_ms": 213.4,
    "p99_ms": 1847.2
  },
  "circuit_breakers": {
    "groq": {
      "state": "closed",
      "failure_count": 0,
      "last_failure_ago_s": null
    }
  }
}
```

---

### `POST /admin/keys`

Create a new API key. Requires an **admin** key. Returns the plaintext key **once** — store it immediately.

**Request body**

```json
{
  "name": "mobile-app",
  "role": "user",
  "rate_limit": 30
}
```

| Field | Type | Default | Description |
|---|---|---|---|
| `name` | string | required | Human-readable label (1–80 chars) |
| `role` | string | `"user"` | `"user"` or `"admin"` |
| `rate_limit` | int | `60` | Max requests per minute for this key (1–10000) |

**Response (201 Created)**

```json
{
  "api_key": "sentri_abc123...",
  "key_id": "key_f3a9c1",
  "name": "mobile-app",
  "role": "user",
  "rate_limit": 30,
  "created_at": "2025-06-22T10:00:00+00:00",
  "message": "Store this key securely — it will not be shown again."
}
```

---

### `GET /admin/keys`

List all API keys with metadata. Plaintext keys are **never** returned. Requires an **admin** key.

**Response**

```json
[
  {
    "key_id": "key_f3a9c1",
    "name": "mobile-app",
    "role": "user",
    "rate_limit": 30,
    "created_at": "2025-06-22T10:00:00+00:00",
    "last_used_at": "2025-06-22T11:42:00+00:00",
    "is_active": true,
    "usage_count": 847
  }
]
```

---

### `GET /admin/keys/{key_id}`

Inspect a single key by its ID. Requires an **admin** key.

```bash
curl http://localhost:8000/admin/keys/key_f3a9c1 \
  -H "X-API-Key: sentri_admin_key_here"
```

Returns the same shape as a single entry from `GET /admin/keys`. Returns `404` if the key ID does not exist.

---

### `DELETE /admin/keys/{key_id}`

Revoke a key immediately. The key record is soft-deleted (kept for audit); the plaintext was never stored. Any subsequent request using the revoked key receives a `401`. Requires an **admin** key.

```bash
curl -X DELETE http://localhost:8000/admin/keys/key_f3a9c1 \
  -H "X-API-Key: sentri_admin_key_here"
```

**Response**

```json
{
  "key_id": "key_f3a9c1",
  "revoked": true,
  "message": "Key 'key_f3a9c1' has been revoked and will be rejected immediately."
}
```

---

### `POST /admin/keys/{key_id}/rotate`

Atomically revoke the old key and issue a replacement with the same `name`, `role`, and `rate_limit`. Returns the new plaintext key once. Requires an **admin** key.

```bash
curl -X POST http://localhost:8000/admin/keys/key_f3a9c1/rotate \
  -H "X-API-Key: sentri_admin_key_here"
```

**Response**

```json
{
  "api_key": "sentri_xyz789...",
  "key_id": "key_a2b4c6",
  "name": "mobile-app",
  "role": "user",
  "rate_limit": 30,
  "created_at": "2025-06-22T12:00:00+00:00",
  "message": "Old key revoked. Store this new key securely — it will not be shown again."
}
```

---

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `GROQ_API_KEY` | Groq API key | required |
| `OPENAI_API_KEY` | OpenAI API key (fallback provider) | optional |
| `REDIS_URL` | Redis connection URL | `redis://localhost:6379` |
| `GATEWAY_ADMIN_KEY` | Bootstrap admin key registered on first startup | optional |
| **Domain / Role** | | |
| `DEFAULT_SYSTEM_PROMPT` | Role instruction sent to the LLM on every request. Change this to repurpose Sentri for any domain. | `You are a helpful DSA tutor.` |
| `DOMAIN_TOPICS` | Comma-separated list of topics the domain policy will allow. Requests not matching any topic are blocked. Leave unset to use the built-in DSA topic list. | *(DSA topics)* |
| `DOMAIN_THRESHOLD` | Cosine similarity cutoff for domain policy (0.0–1.0). Lower = more permissive, higher = stricter. | `0.30` |
| **Cache** | | |
| `SIMILARITY_THRESHOLD` | Cosine similarity threshold for semantic cache hits | `0.85` |
| `CACHE_TTL` | Cache entry TTL in seconds | `3600` |
| **Guardrails** | | |
| `ENABLE_PII_DETECTION` | Toggle PII scrubbing on input and output | `true` |
| `ENABLE_TOXICITY_CHECK` | Toggle toxicity check | `true` |
| `ENABLE_DOMAIN_POLICY` | Toggle domain policy validator entirely | `true` |
| **Rate Limiting** | | |
| `RATE_LIMIT_REQUESTS` | Global default max requests per window | `60` |
| `RATE_LIMIT_WINDOW` | Rate limit window in seconds | `60` |
| **Circuit Breaker** | | |
| `CIRCUIT_FAILURE_THRESHOLD` | Failures before circuit opens | `5` |
| `CIRCUIT_RECOVERY_TIMEOUT` | Seconds before OPEN → HALF_OPEN transition | `60.0` |
| **App** | | |
| `APP_ENV` | Environment label (`development` / `production`) | `development` |
| `LOG_LEVEL` | Logging level | `INFO` |

---

## Design Decisions

**Why SHA-256 for key storage instead of bcrypt?**
API keys are validated on every request — bcrypt's intentional slowness (~100ms) would add unacceptable overhead at scale. SHA-256 is fast (~0ms) and sufficient here because the keys themselves have 256 bits of entropy from `secrets.token_hex(32)`, making brute-force infeasible regardless of the hash function. Bcrypt is designed for low-entropy passwords, not high-entropy tokens.

**Why sentence-transformers instead of OpenAI embeddings?**
OpenAI's embedding API adds network latency and cost to every cache lookup, which defeats the purpose of caching. `all-MiniLM-L6-v2` runs locally, produces 384-dim embeddings in ~5ms, and performs well on short Q&A text — the primary use case here.

**Why an asyncio.Event stampede guard instead of a Redis lock?**
A Redis distributed lock (`SETNX`) adds a network round-trip to every cache miss. Since the gateway is single-process (uvicorn with one worker), in-process `asyncio.Event` objects are simpler, have zero network overhead, and provide the same guarantee. For multi-process deployments, this should be replaced with a Redis-backed lock.

**Why layer exact cache before semantic cache?**
Exact hash lookup is O(1) with no model inference. For repeated identical queries (the hot path in any real workload), this avoids even the embedding computation. The semantic cache handles paraphrase matching as a fallback.

**Why build the injection detector from scratch instead of a library?**
Libraries like `rebuff` use LLM-as-judge for injection detection, adding 200–500ms per request. Regex-based pattern matching covers the vast majority of real-world attacks at ~0ms. The two-pass normalisation (Unicode + base64) additionally catches evasion attempts that naive regex misses.

**Why Redis Stack over Pinecone/Weaviate for vector search?**
Redis Stack collapses the cache store, exact-match store, rate-limit counters, API key store, and vector index into a single infrastructure component. This avoids second network hops to external vector DBs on every cache lookup and keeps the operational footprint minimal.

**Why plugin-style guardrail registration?**
The original pipeline was hardwired — adding a guardrail meant editing the pipeline file directly. The registry pattern (`pipeline.register(MyGuardrail())`) lets you drop a new file in `app/guardrails/`, register it in `main.py`, and redeploy. The pipeline file itself never changes, reducing the risk of accidental breakage.

**Why soft-delete API keys instead of hard-delete?**
Revoked keys are marked `is_active=0` but the record is retained. This preserves a full audit trail — you can see when a key was created, how many times it was used, and when it was revoked. Hard-deleting would make it impossible to investigate suspicious usage after the fact.

---

## Author

**Vatsal Agarwal**
GitHub: [@agvatsal1312](https://github.com/agvatsal1312)
Repository: [github.com/agvatsal1312/sentri](https://github.com/agvatsal1312/sentri)
