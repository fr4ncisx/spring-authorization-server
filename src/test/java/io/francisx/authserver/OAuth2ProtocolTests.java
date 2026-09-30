package io.francisx.authserver;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.hamcrest.Matchers.greaterThan;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
class OAuth2ProtocolTests {

    @Autowired
    private WebApplicationContext context;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(context)
                .apply(springSecurity())
                .build();
    }

    @Test
    void shouldIssueTokenForClientCredentials() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                .param("grant_type", "client_credentials")
                .param("scope", "user.read")
                .with(httpBasic("user-client", "test-secret-key-32-chars-long-minimum!")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in", greaterThan(0)));
    }

    @Test
    void shouldRejectInvalidClientSecret() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                .param("grant_type", "client_credentials")
                .param("scope", "user.read")
                .with(httpBasic("user-client", "invalid-secret-key")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"));
    }

    @Test
    void shouldRejectUnsupportedGrantType() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                .param("grant_type", "password")
                .with(httpBasic("user-client", "test-secret-key-32-chars-long-minimum!")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("unsupported_grant_type"));
    }

    @Test
    void shouldExposeOpenIdDiscoveryConfiguration() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value("http://localhost:9000"))
                .andExpect(jsonPath("$.token_endpoint").value("http://localhost:9000/oauth2/token"))
                .andExpect(jsonPath("$.jwks_uri").value("http://localhost:9000/oauth2/jwks"))
                .andExpect(jsonPath("$.response_types_supported").isArray());
    }

    @Test
    void shouldExposePublicJwkSet() throws Exception {
        mockMvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].n").isNotEmpty())
                .andExpect(jsonPath("$.keys[0].e").isNotEmpty())
                .andExpect(jsonPath("$.keys[0].kid").isNotEmpty());
    }
}
