package io.francisx.authserver;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class PostgreSQLTestcontainersIntegrationTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:18-alpine");

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private OAuth2AuthorizationService authorizationService;

    @Autowired
    private OAuth2AuthorizationConsentService authorizationConsentService;

    @Test
    void shouldPersistAndRetrieveRegisteredClientFromPostgreSql() {
        RegisteredClient client = registeredClientRepository.findByClientId("user-client");
        assertThat(client).isNotNull();
        assertThat(client.getClientId()).isEqualTo("user-client");
    }

    @Test
    void shouldPersistAndRetrieveAuthorizationFromPostgreSql() {
        RegisteredClient registeredClient = registeredClientRepository.findByClientId("user-client");
        assertThat(registeredClient).isNotNull();

        String authorizationId = UUID.randomUUID().toString();
        String tokenValue = "test-token-" + UUID.randomUUID();
        Instant issuedAt = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiresAt = issuedAt.plus(1, ChronoUnit.HOURS);
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                tokenValue,
                issuedAt,
                expiresAt,
                Set.of("user.read")
        );

        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(authorizationId)
                .principalName("test-user")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizedScopes(Set.of("user.read"))
                .accessToken(accessToken)
                .build();

        authorizationService.save(authorization);

        OAuth2Authorization retrievedById = authorizationService.findById(authorizationId);
        assertThat(retrievedById).isNotNull();
        assertThat(retrievedById.getId()).isEqualTo(authorizationId);
        assertThat(retrievedById.getPrincipalName()).isEqualTo("test-user");

        OAuth2Authorization retrievedByToken = authorizationService.findByToken(tokenValue, OAuth2TokenType.ACCESS_TOKEN);
        assertThat(retrievedByToken).isNotNull();
        assertThat(retrievedByToken.getId()).isEqualTo(authorizationId);

        authorizationService.remove(authorization);

        OAuth2Authorization afterRemoval = authorizationService.findById(authorizationId);
        assertThat(afterRemoval).isNull();
    }

    @Test
    void shouldPersistAndRetrieveAuthorizationConsentFromPostgreSql() {
        RegisteredClient registeredClient = registeredClientRepository.findByClientId("user-client");
        assertThat(registeredClient).isNotNull();

        OAuth2AuthorizationConsent consent = OAuth2AuthorizationConsent.withId(registeredClient.getId(), "consent-user")
                .scope("user.read")
                .build();

        authorizationConsentService.save(consent);

        OAuth2AuthorizationConsent retrievedConsent = authorizationConsentService.findById(registeredClient.getId(), "consent-user");
        assertThat(retrievedConsent).isNotNull();
        assertThat(retrievedConsent.getScopes()).contains("user.read");

        authorizationConsentService.remove(consent);

        OAuth2AuthorizationConsent afterRemoval = authorizationConsentService.findById(registeredClient.getId(), "consent-user");
        assertThat(afterRemoval).isNull();
    }
}
