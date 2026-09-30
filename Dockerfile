FROM eclipse-temurin:25-alpine AS builder
WORKDIR /workspace

COPY pom.xml mvnw ./
COPY .mvn .mvn
RUN chmod +x mvnw && ./mvnw -B dependency:go-offline

COPY src src
RUN ./mvnw -B clean package -DskipTests
RUN java -Djarmode=tools -jar target/*.jar extract --layers --destination extracted

FROM eclipse-temurin:25-jre-alpine AS runtime

RUN apk update && apk add --no-cache curl && rm -rf /var/cache/apk/*

RUN addgroup --system --gid 10001 appgroup && \
    adduser --system --uid 10001 --ingroup appgroup --no-create-home --disabled-password appuser

WORKDIR /app

COPY --from=builder --chown=appuser:appgroup /workspace/extracted/dependencies/ ./
COPY --from=builder --chown=appuser:appgroup /workspace/extracted/spring-boot-loader/ ./
COPY --from=builder --chown=appuser:appgroup /workspace/extracted/snapshot-dependencies/ ./
COPY --from=builder --chown=appuser:appgroup /workspace/extracted/application/ ./

RUN chmod -R 550 /app

USER 10001:10001

EXPOSE 9000

HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD curl --silent --fail http://localhost:9000/actuator/health/liveness || exit 1

ENTRYPOINT ["java", \
  "-XX:+UseContainerSupport", \
  "-XX:MaxRAMPercentage=75.0", \
  "-XX:+ExitOnOutOfMemoryError", \
  "-Djava.security.egd=file:/dev/./urandom", \
  "org.springframework.boot.loader.launch.JarLauncher"]
