<div align="center">

# Spring Authorization Server

**OAuth2 and OpenID Connect identity provider for microservices**

Cloud-native token issuance and authentication server for distributed service architectures.

[![Java](https://img.shields.io/badge/Java-25-ED8B00?style=flat-square&logo=openjdk&logoColor=white)](pom.xml)
[![Spring Boot](https://img.shields.io/badge/Spring_Boot-4.1.1-6DB33F?style=flat-square&logo=springboot&logoColor=white)](pom.xml)
[![Spring Security](https://img.shields.io/badge/Spring_Security-7.1.1-6DB33F?style=flat-square&logo=springsecurity&logoColor=white)](pom.xml)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-18-4169E1?style=flat-square&logo=postgresql&logoColor=white)](docker-compose.yml)
[![Testcontainers](https://img.shields.io/badge/Testcontainers-1.20.4-2496ED?style=flat-square&logo=docker&logoColor=white)](src/test/java/io/francisx/authserver/PostgreSQLTestcontainersIntegrationTest.java)
[![Flyway](https://img.shields.io/badge/Flyway-12.4.0-CC0200?style=flat-square&logo=flyway&logoColor=white)](src/main/resources/db/migration)
[![OAuth 2.1](https://img.shields.io/badge/OAuth-2.1_%2F_OIDC-000000?style=flat-square&logo=openid&logoColor=white)](https://oauth.net/2.1/)
[![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED?style=flat-square&logo=docker&logoColor=white)](Dockerfile)
[![OWASP Hardened](https://img.shields.io/badge/OWASP-Hardened-005B94?style=flat-square&logo=owasp&logoColor=white)](Dockerfile)

[**Quickstart**](#quickstart) · [**Features**](#features) · [**Components**](#components) · [**Installation**](#installation) · [**Usage**](#usage) · [**Troubleshooting**](#troubleshooting)

</div>

---

## Quickstart

Configure your environment file, start the database and service stack, and verify the healthcheck probe.

**1. Copy the environment configuration**

```bash
cp .env.example .env
```

**2. Start PostgreSQL standalone for local development**

```bash
docker compose up -d postgres
```

**3. Or start the full container stack**

```bash
docker compose up -d --build
```

**4. Verify server health**

```bash
curl -i http://localhost:9000/actuator/health/liveness
```

> **Note:** The service runs on port `9000` by default. Verify that your client redirect URIs match your frontend origin before requesting tokens.

---

## Table of Contents

- [Quickstart](#quickstart)
- [Features](#features)
- [Components](#components)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Build Instructions](#build-instructions)
  - [Running Tests](#running-tests)
  - [Environment Variables](#environment-variables)
- [Usage](#usage)
  - [Docker Compose Orchestration](#docker-compose-orchestration)
  - [OAuth2 Protocol Flow](#oauth2-protocol-flow)
- [Database Persistence and Migrations](#database-persistence-and-migrations)
- [Troubleshooting](#troubleshooting)
- [Feedback](#feedback)

---

## Features

| Feature | Description |
|---|---|
| **Enterprise Persistence** | Persists registered OAuth2 clients, active authorizations, and user consents in PostgreSQL 18 with automated Flyway versioned migrations. |
| **Protocol Compliance** | Issues signed JWT access tokens and OpenID Connect ID tokens via standard authorization code and client credentials grants. |
| **PKCE Enforcement** | Enforces Proof Key for Code Exchange on authorization code flows to prevent interception attacks. |
| **Cloud-Native Discovery** | Resolves external services through container network DNS rather than centralized registry servers. |
| **Token Caching** | Reuses internal client credentials tokens across authentication requests to prevent thread starvation under concurrency. |
| **Container Hardening** | Executes inside an unprivileged user space, dedicated bridge network, localhost port isolation, log rotation, and ulimit protections. |
| **Ephemeral Testcontainers** | Validates schema migration, client bootstrapping, and JDBC token persistence in real PostgreSQL 18 containers via Testcontainers. |

---

## Components

The system consists of six main architectural components:

1. **Security Configuration** (`src/main/java/io/francisx/authserver/infrastructure/security/SecurityConfig.java`) — Configures dual security filter chains, cryptographic JWK key pairs, JDBC client and authorization repositories, and automated client bootstrapping.
2. **Database Migrations** (`src/main/resources/db/migration/V1__oauth2_schema.sql`) — Manages versioned Flyway DDL migrations for client registries, authorization sessions, and user consents.
3. **Authentication Provider** (`src/main/java/io/francisx/authserver/infrastructure/security/CustomAuthProvider.java`) — Validates user credentials against the user service with timing-attack mitigation.
4. **Token Service** (`src/main/java/io/francisx/authserver/infrastructure/security/TokenService.java`) — Handles internal service tokens with thread-safe caching and connection pooling.
5. **Declarative HTTP Client** (`src/main/java/io/francisx/authserver/infrastructure/client/CustomFeignClient.java`) — Communicates with the upstream user service over DNS-backed endpoints.
6. **CORS Configuration** (`src/main/java/io/francisx/authserver/domain/configuration/CorsConfiguration.java`) — Sanitizes cross-origin request headers and enforces safe HTTP methods.

---

## Installation

### Prerequisites

- **Java Development Kit** 25 or newer
- **Docker Engine** 24 or newer
- **Docker Compose** 2.20 or newer

### Build Instructions

<details open>
<summary><b>Local Maven Wrapper</b></summary>

```bash
./mvnw clean package -DskipTests
```

</details>

<details>
<summary><b>Docker Multi-Stage Build</b></summary>

```bash
docker build -t auth-server:latest .
```

</details>

### Running Tests

Execute the automated unit and mock test suite covering OAuth2 protocol compliance, security boundaries, Flyway migration execution against H2 in PostgreSQL compatibility mode, timing-attack mitigation, and token service concurrency:

```bash
./mvnw clean test
```

Execute full verification including Testcontainers integration tests against real PostgreSQL 18:

```bash
./mvnw clean verify
```

The integration test suite (`PostgreSQLTestcontainersIntegrationTest`) automatically spawns an ephemeral `postgres:18-alpine` container using Spring Boot `@ServiceConnection` and `@Testcontainers`. It validates:

| Verification Target | Scope |
|---|---|
| **Flyway Schema Migration** | Verifies automatic DDL execution of `V1__oauth2_schema.sql` against native PostgreSQL 18 engine. |
| **Client Bootstrap & Lookup** | Asserts idempotent persistence and retrieval of `user-client` via `JdbcRegisteredClientRepository`. |
| **OAuth2 Authorization Lifecycle** | Tests full lifecycle (save, find by ID, find by token, and deletion) of `OAuth2Authorization` via `JdbcOAuth2AuthorizationService`. |
| **Consent & Scope Delegations** | Validates persistence, scope attribution, and revocation of `OAuth2AuthorizationConsent` via `JdbcOAuth2AuthorizationConsentService`. |


### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SERVER_PORT` | `9000` | Port on which the HTTP server listens. |
| `ALLOWED_ORIGINS_URI_CORS` | `http://localhost:3000` | Allowed origins for cross-origin requests. |
| `LOGIN_REDIRECT` | `http://127.0.0.1:8080/login/oauth2/code/oauth2-client` | Authorized redirect target following user authentication. |
| `LOGOUT_REDIRECT` | `http://127.0.0.1:8080/` | Target location following user logout. |
| `CLIENT_SECRET` | `test-secret-key-32-chars-long-minimum!` | Secret key used for authenticating client applications. |
| `AUTHSERVER_URI` | `http://localhost:9000` | Public base address of this authorization server. |
| `TOKEN_URI` | `http://localhost:9000/oauth2/token` | Canonical endpoint where OAuth2 tokens are minted. |
| `CLIENT_USER_SERVICE_SCOPE` | `user.read` | Required OAuth2 scope to query user information. |
| `CLIENTID_USER_SERVICE` | `user-client` | Client identifier used for internal microservice communication. |
| `CLIENTID_OIDC` | `oidc-client` | Client identifier for front-channel authentication. |
| `USER_SERVICE_URL` | `http://user-service:8080` | Network address of the upstream user service. |
| `POSTGRES_DB` | `auth_db` | PostgreSQL database name for OAuth2 persistence. |
| `POSTGRES_USER` | `postgres` | Administrative database user account. |
| `POSTGRES_PASSWORD` | `postgres` | Password for PostgreSQL user authentication. |
| `POSTGRES_PORT` | `5432` | Exposed host port for the PostgreSQL container. |
| `SPRING_DATASOURCE_URL` | `jdbc:postgresql://localhost:5432/auth_db` | JDBC connection URL for Spring Authorization Server. |
| `SPRING_DATASOURCE_USERNAME` | `postgres` | Username for JDBC connection. |
| `SPRING_DATASOURCE_PASSWORD` | `postgres` | Password for JDBC connection. |

---

## Usage

### Docker Compose Orchestration

The container stack coordinates the authorization service and PostgreSQL 18 database with enterprise security hardening, healthcheck probes, and network isolation.

#### Security Hardening Specifications

| Control | Implementation | Security Objective |
|---|---|---|
| **Localhost DB Port Binding** | `127.0.0.1:${POSTGRES_PORT:-5432}:5432` | Prevents unintended database port exposure to public or bridge network interfaces. |
| **Dedicated Bridge Network** | `auth-network` (`name: auth_network`) | Segregates service inter-communication into an isolated software-defined subnet. |
| **Log Rotation Policies** | `driver: json-file`, `max-size: 10m`, `max-file: 3` | Mitigates Disk Full Denial of Service (DoS) from unbounded logging. |
| **Active Healthcheck Probes** | `curl -f http://localhost:9000/actuator/health/liveness` | Ensures orchestration dependencies start only after verified upstream health. |
| **Graceful Shutdown** | `stop_grace_period: 30s` | Guarantees safe in-flight HTTP request completion and clean JDBC connection pool draining. |
| **Resource & File Descriptor Limits** | `nofile: soft: 65536, hard: 65536`, memory & CPU caps | Protects host from container memory leaks, thread starvation, and file descriptor exhaustion. |
| **Privilege Hardening** | `security_opt: no-new-privileges:true` | Prevents privilege escalation within container runtimes. |

**Start PostgreSQL Database Standalone**

```bash
docker compose up -d postgres
```

**Start the Complete Container Stack**

```bash
docker compose up -d --build
```

**Check Service Status and Health**

```bash
docker compose ps
```

**View Container Logs**

```bash
docker compose logs -f auth-service
```

**Stop Container Stack**

```bash
docker compose down
```

### OAuth2 Protocol Flow

**1. OpenID Discovery**

Query configuration metadata to inspect endpoints and supported capabilities:

```bash
curl -s http://localhost:9000/.well-known/openid-configuration
```

**2. JWK Set Endpoint**

Fetch public cryptographic keys to verify token signatures in downstream resource servers:

```bash
curl -s http://localhost:9000/oauth2/jwks
```

**3. Mint Token via Client Credentials Grant**

Authenticate service clients and request JWT access tokens:

```bash
curl -s -X POST http://localhost:9000/oauth2/token \
  -u user-client:test-secret-key-32-chars-long-minimum! \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&scope=user.read"
```

---

## Database Persistence and Migrations

Persistence is backed by PostgreSQL using standard Spring Authorization Server tables:

| Table | Purpose |
|---|---|
| `oauth2_registered_client` | Client registration metadata, secrets, grant types, redirect URIs, scopes, and client settings. |
| `oauth2_authorization` | Active OAuth2 authorization sessions, authorization codes, access tokens, refresh tokens, and OIDC ID tokens. |
| `oauth2_authorization_consent` | Granted user consents and delegated authorities per client. |

Flyway executes `V1__oauth2_schema.sql` automatically upon application startup. Default clients (`user-client` and `oidc-client`) are bootstrapped on initial startup via an idempotent application runner.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| **PostgreSQL container unhealthy** | Check database credentials in `.env` and verify port `5432` availability. |
| **Auth service waiting for postgres** | Verify that `auth-postgres` passes health checks via `docker compose ps`. |
| **Authentication fails with 401** | Confirm that `USER_SERVICE_URL` points to an active user service instance and check credentials. |
| **CORS preflight rejected** | Add your client origin to `ALLOWED_ORIGINS_URI_CORS` in `.env` and restart the container. |
| **Connection refused on localhost** | Ensure no local process binds to port `9000` or `5432` before running Docker Compose. |

---

## Feedback

File issue reports and technical questions through the project issue tracker.

---

<div align="center">

**Deploy secure authentication for distributed systems.**

</div>