package io.francisx.authserver.infrastructure.security;

import io.francisx.authserver.config.properties.AppSecurityProperties;
import io.francisx.authserver.config.properties.OAuth2ClientProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

@Service
public class TokenService {

    private final AppSecurityProperties appSecurityProperties;
    private final OAuth2ClientProperties oAuth2ClientProperties;
    private final RestTemplate restTemplate;
    private final AtomicReference<CachedToken> tokenCache = new AtomicReference<>();

    @Autowired
    public TokenService(AppSecurityProperties appSecurityProperties, OAuth2ClientProperties oAuth2ClientProperties) {
        this(appSecurityProperties, oAuth2ClientProperties, createDefaultRestTemplate());
    }

    public TokenService(AppSecurityProperties appSecurityProperties, OAuth2ClientProperties oAuth2ClientProperties, RestTemplate restTemplate) {
        this.appSecurityProperties = appSecurityProperties;
        this.oAuth2ClientProperties = oAuth2ClientProperties;
        this.restTemplate = restTemplate;
    }

    private static RestTemplate createDefaultRestTemplate() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(Duration.ofSeconds(2));
        factory.setReadTimeout(Duration.ofSeconds(4));
        return new RestTemplate(factory);
    }

    public String getClientCredentialsToken() {
        CachedToken cached = tokenCache.get();
        if (cached != null && cached.isValid()) {
            return cached.token();
        }
        synchronized (this) {
            cached = tokenCache.get();
            if (cached != null && cached.isValid()) {
                return cached.token();
            }
            CachedToken refreshed = fetchToken();
            tokenCache.set(refreshed);
            return refreshed.token();
        }
    }

    private CachedToken fetchToken() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.setBasicAuth(
                oAuth2ClientProperties.clientid().serviceClient(),
                appSecurityProperties.secretKey()
        );

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "client_credentials");
        params.add("scope", oAuth2ClientProperties.client().scope());

        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(params, headers);

        ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                appSecurityProperties.token().uri(),
                HttpMethod.POST,
                entity,
                new ParameterizedTypeReference<>() {}
        );

        Map<String, Object> body = Optional.ofNullable(response.getBody())
                .orElseThrow(() -> new HttpServerErrorException(HttpStatus.BAD_REQUEST, "Token Response Failed"));

        String token = body.get("access_token").toString();
        long expiresIn = 300L;
        Object expObj = body.get("expires_in");
        if (expObj instanceof Number number) {
            expiresIn = number.longValue();
        }
        Instant expiresAt = Instant.now().plusSeconds(Math.max(10L, expiresIn - 30L));
        return new CachedToken(token, expiresAt);
    }

    private record CachedToken(String token, Instant expiresAt) {
        boolean isValid() {
            return Instant.now().isBefore(expiresAt);
        }
    }
}
