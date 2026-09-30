package io.francisx.authserver;

import io.francisx.authserver.domain.dto.response.UserResponse;
import io.francisx.authserver.infrastructure.client.UserClient;
import io.francisx.authserver.infrastructure.security.CustomAuthProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CustomAuthProviderTest {

    @Mock
    private UserClient userClient;

    @Mock
    private PasswordEncoder passwordEncoder;

    private CustomAuthProvider authProvider;

    @BeforeEach
    void setUp() {
        this.authProvider = new CustomAuthProvider(userClient, passwordEncoder);
    }

    @Test
    void shouldAuthenticateSuccessfullyWhenCredentialsAreValid() {
        UserResponse user = new UserResponse("john", "encoded-secret", List.of("ROLE_USER"));
        when(userClient.findByUsername("john")).thenReturn(user);
        when(passwordEncoder.matches("raw-secret", "encoded-secret")).thenReturn(true);

        Authentication token = new UsernamePasswordAuthenticationToken("john", "raw-secret");
        Authentication result = authProvider.authenticate(token);

        assertThat(result).isNotNull();
        assertThat(result.getName()).isEqualTo("john");
        assertThat(result.getAuthorities()).hasSize(1);
        assertThat(result.getAuthorities().iterator().next().getAuthority()).isEqualTo("ROLE_USER");
    }

    @Test
    void shouldRejectWhenPasswordDoesNotMatch() {
        UserResponse user = new UserResponse("john", "encoded-secret", List.of("ROLE_USER"));
        when(userClient.findByUsername("john")).thenReturn(user);
        when(passwordEncoder.matches("wrong-secret", "encoded-secret")).thenReturn(false);

        Authentication token = new UsernamePasswordAuthenticationToken("john", "wrong-secret");

        assertThatThrownBy(() -> authProvider.authenticate(token))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Bad credentials");
    }

    @Test
    void shouldExecuteDummyHashToPreventTimingAttacksWhenUserNotFound() {
        when(userClient.findByUsername("ghost")).thenReturn(null);

        Authentication token = new UsernamePasswordAuthenticationToken("ghost", "any-secret");

        assertThatThrownBy(() -> authProvider.authenticate(token))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Bad credentials");

        verify(passwordEncoder).matches(eq("any-secret"), anyString());
    }

    @Test
    void shouldExecuteDummyHashWhenClientThrowsNotFound() {
        HttpClientErrorException.NotFound notFound = mock(HttpClientErrorException.NotFound.class);
        when(userClient.findByUsername("ghost")).thenThrow(notFound);

        Authentication token = new UsernamePasswordAuthenticationToken("ghost", "any-secret");

        assertThatThrownBy(() -> authProvider.authenticate(token))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Bad credentials");

        verify(passwordEncoder).matches(eq("any-secret"), anyString());
    }

    @Test
    void shouldHandleUpstreamServiceFailure() {
        RestClientException serverError = mock(RestClientException.class);
        when(userClient.findByUsername("john")).thenThrow(serverError);

        Authentication token = new UsernamePasswordAuthenticationToken("john", "secret");

        assertThatThrownBy(() -> authProvider.authenticate(token))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Authentication service unavailable");
    }

    @Test
    void shouldSupportUsernamePasswordAuthenticationToken() {
        assertThat(authProvider.supports(UsernamePasswordAuthenticationToken.class)).isTrue();
        assertThat(authProvider.supports(Authentication.class)).isFalse();
    }
}
