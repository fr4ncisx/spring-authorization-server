package io.francisx.authserver;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
class SecurityHardeningTests {

    @Autowired
    private WebApplicationContext context;

    private MockMvc mockMvc;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @BeforeEach
    void setUp() {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(context)
                .apply(springSecurity())
                .build();
    }

    @Test
    void healthLivenessShouldBePubliclyAccessible() throws Exception {
        mockMvc.perform(get("/actuator/health/liveness"))
                .andExpect(status().isOk());
    }

    @Test
    void unauthenticatedAccessToActuatorEnvShouldRedirectToLogin() throws Exception {
        mockMvc.perform(get("/actuator/env"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login"));
    }

    @Test
    @WithMockUser
    void authenticatedUserAccessToDisabledActuatorEndpointShouldReturnNotFound() throws Exception {
        mockMvc.perform(get("/actuator/env"))
                .andExpect(status().isNotFound());

        mockMvc.perform(get("/actuator/beans"))
                .andExpect(status().isNotFound());
    }

    @Test
    void oidcClientShouldEnforcePkce() {
        RegisteredClient client = registeredClientRepository.findByClientId("oidc-client");
        assertThat(client).isNotNull();
        assertThat(client.getClientSettings().isRequireProofKey()).isTrue();
    }
}
