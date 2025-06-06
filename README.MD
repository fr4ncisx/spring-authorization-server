## 🛡️ Authorization Server Template for Microservices

This project is a starter template for building an OAuth2 Authorization Server using Spring Authorization Server, fully
compatible with microservices architectures that require secure authentication, service discovery, and seamless
inter-service communication.

> [!IMPORTANT]
> This project requires Eureka Sever running and user-service running in parallel with Eureka Client

## 🔧 Included Components

| Component                     | Description                                                                                          |
|-------------------------------|------------------------------------------------------------------------------------------------------|
| ✅ Java JDK 21                 | Latest long-term support version of Java, with improved performance and modern syntax support.       |
| ✅ Spring Boot 3.5.0           | Core framework for building the application, fully compatible with the latest Spring Cloud releases. |
| ✅ Spring Cloud 2025.0.0       | Provides tools for distributed systems including service discovery                                   |
| ✅ Spring Cloud OpenFeign      | Declarative HTTP client used to communicate with other microservices like user-service.              |
| ✅ Netflix Eureka Client       | Enables the service to register with and be discovered by a Eureka Server.                           |
| ✅ Docker Compose              | Container orchestration tool to easily run this service along with its dependencies locally.         |
| ✅ Authorization Server OAuth2 | Implements a secure Authorization Server using Spring Authorization Server, supporting OAuth2.       |

## ⚙️ Required Environment Variables

| Variable                  | Description                                            | Example values                      |
|---------------------------|--------------------------------------------------------|-------------------------------------|
| SERVER_PORT               | Port on which the server will run                      | 9000                                |
| ALLOWED_ORIGINS_URI_CORS  | CORS allowed origins                                   | http://localhost:4200               |
| LOGIN_REDIRECT            | 	Redirect URI after login success                      | 	http://localhost:4200/dashboard    |
| LOGOUT_REDIRECT           | 	Redirect URI after logout                             | 	http://localhost:4200/login        |
| CLIENT_SECRET             | 	Secret key used for signing JWTs or encrypting data   | 	supersecretkey123!                 |
| AUTHSERVER_URI            | 	Public URI of this auth server                        | 	http://localhost:9000              |
| TOKEN_URI                 | 	URI endpoint where tokens are issued                  | 	http://localhost:9000/oauth2/token |
| CLIENT_USER_SERVICE_SCOPE | 	OAuth2 scope required by user-service                 | 	user.read                          |
| CLIENTID_USER_SERVICE     | 	OAuth2 Client ID for internal service-to-service auth | 	user-service-client                |
| CLIENTID_OIDC             | 	OAuth2 Client ID for OIDC-enabled frontend            | 	frontend-client                    |
| FEIGN_USER_SERVICE_NAME   | 	Logical name of user-service in Eureka                | 	user-service                       |
| EUREKA_SERVER_URI         | 	Eureka discovery server URI                           | 	http://localhost:8761/eureka/      |

💡 You can define these variables in a .env file if using Docker Compose, or export them manually before running the
application locally.

## 🧪 Running Locally

Build the project:

> ```./mvnw clean install```

Run with Docker Compose **(Requires Docker Desktop)**:

> ```docker-compose up --build```

Access the Authorization Server:

> ```http://localhost:9000```

## 📘 References

[Spring Authorization Server Docs](https://docs.spring.io/spring-authorization-server/reference/overview.html)

[OAuth 2.1 Specification (IETF)](https://oauth.net/2.1/)

[Spring Cloud OpenFeign](https://docs.spring.io/spring-cloud-openfeign/docs/current/reference/html/)

[Eureka Service Discovery](https://cloud.spring.io/spring-cloud-netflix/reference/html/)