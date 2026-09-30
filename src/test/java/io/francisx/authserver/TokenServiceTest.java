package io.francisx.authserver;

import io.francisx.authserver.config.properties.AppSecurityProperties;
import io.francisx.authserver.config.properties.OAuth2ClientProperties;
import io.francisx.authserver.infrastructure.security.TokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TokenServiceTest {

    @Mock
    private RestTemplate restTemplate;

    private TokenService tokenService;

    @BeforeEach
    void setUp() {
        AppSecurityProperties securityProps = new AppSecurityProperties(
                "test-secret-key-32-chars-long-minimum!",
                "http://localhost:9000",
                new AppSecurityProperties.TokenProperties("http://localhost:9000/oauth2/token")
        );
        OAuth2ClientProperties oauth2Props = new OAuth2ClientProperties(
                new OAuth2ClientProperties.ClientProperties("user.read"),
                new OAuth2ClientProperties.ClientIdProperties("user-client", "oidc-client")
        );
        this.tokenService = new TokenService(securityProps, oauth2Props, restTemplate);
    }

    @Test
    void shouldFetchAndCacheTokenAcrossMultipleCalls() {
        Map<String, Object> responseBody = Map.of(
                "access_token", "jwt-mock-token-abc",
                "expires_in", 300
        );
        ResponseEntity<Map<String, Object>> response = new ResponseEntity<>(responseBody, HttpStatus.OK);

        when(restTemplate.exchange(
                eq("http://localhost:9000/oauth2/token"),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                any(ParameterizedTypeReference.class)
        )).thenReturn(response);

        String firstToken = tokenService.getClientCredentialsToken();
        String secondToken = tokenService.getClientCredentialsToken();
        String thirdToken = tokenService.getClientCredentialsToken();

        assertThat(firstToken).isEqualTo("jwt-mock-token-abc");
        assertThat(secondToken).isEqualTo("jwt-mock-token-abc");
        assertThat(thirdToken).isEqualTo("jwt-mock-token-abc");

        verify(restTemplate, times(1)).exchange(
                eq("http://localhost:9000/oauth2/token"),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                any(ParameterizedTypeReference.class)
        );
    }

    @Test
    void shouldHandleConcurrentRequestsSafelyWithoutRedundantCalls() throws Exception {
        Map<String, Object> responseBody = Map.of(
                "access_token", "jwt-concurrent-token-xyz",
                "expires_in", 600
        );
        ResponseEntity<Map<String, Object>> response = new ResponseEntity<>(responseBody, HttpStatus.OK);

        when(restTemplate.exchange(
                eq("http://localhost:9000/oauth2/token"),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                any(ParameterizedTypeReference.class)
        )).thenReturn(response);

        int threadCount = 20;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);
        List<String> results = Collections.synchronizedList(new ArrayList<>());

        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    String token = tokenService.getClientCredentialsToken();
                    results.add(token);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        boolean finished = doneLatch.await(5, TimeUnit.SECONDS);
        executor.shutdown();

        assertThat(finished).isTrue();
        assertThat(results).hasSize(threadCount);
        assertThat(results).allMatch(token -> token.equals("jwt-concurrent-token-xyz"));

        verify(restTemplate, times(1)).exchange(
                eq("http://localhost:9000/oauth2/token"),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                any(ParameterizedTypeReference.class)
        );
    }
}
