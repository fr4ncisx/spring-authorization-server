package io.francisx.authserver;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
class CorsSecurityTests {

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private CorsConfigurationSource corsConfigurationSource;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(context)
                .apply(springSecurity())
                .build();
    }

    @Test
    void shouldAllowConfiguredOriginForPreflightRequest() throws Exception {
        mockMvc.perform(options("/oauth2/token")
                .header("Origin", "http://localhost:3000")
                .header("Access-Control-Request-Method", "POST"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:3000"));
    }

    @Test
    void shouldExcludeInsecureHttpMethodsFromCorsConfiguration() {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/oauth2/token");
        request.addHeader("Origin", "http://localhost:3000");

        CorsConfiguration config = corsConfigurationSource.getCorsConfiguration(request);

        assertThat(config).isNotNull();
        assertThat(config.getAllowedMethods()).contains("GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD");
        assertThat(config.getAllowedMethods()).doesNotContain("TRACE", "CONNECT");
    }
}
