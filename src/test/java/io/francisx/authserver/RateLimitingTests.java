package io.francisx.authserver;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
class RateLimitingTests {

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
    void rateLimitExceededAfterFifteenRequestsReturns429() throws Exception {
        String testIp = "203.0.113.195";

        for (int i = 0; i < 15; i++) {
            mockMvc.perform(post("/oauth2/token")
                    .header("X-Forwarded-For", testIp)
                    .param("grant_type", "client_credentials")
                    .param("scope", "user.read")
                    .with(httpBasic("user-client", "test-secret-key-32-chars-long-minimum!")))
                    .andExpect(status().isOk());
        }

        mockMvc.perform(post("/oauth2/token")
                .header("X-Forwarded-For", testIp)
                .param("grant_type", "client_credentials")
                .param("scope", "user.read")
                .with(httpBasic("user-client", "test-secret-key-32-chars-long-minimum!")))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "60"))
                .andExpect(jsonPath("$.status").value(429))
                .andExpect(jsonPath("$.title").value("Too Many Requests"))
                .andExpect(jsonPath("$.detail").value("Rate limit exceeded. Try again in 60 seconds."));
    }
}
