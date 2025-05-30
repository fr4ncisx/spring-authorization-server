FROM amazoncorretto:21-alpine

WORKDIR /app

COPY pom.xml ./
COPY mvnw ./
COPY .mvn .mvn

RUN ./mvnw dependency:go-offline -B

COPY src ./src

RUN ./mvnw clean package -DskipTests && cp target/*.jar spring-auth-server-1.0.jar

EXPOSE 9000

ENTRYPOINT ["java", "-jar", "spring-auth-server-1.0.jar"]