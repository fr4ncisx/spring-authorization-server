package io.francisx.authserver;

import io.francisx.authserver.domain.exception.GlobalExceptionHandler;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.client.RestClientException;

import static org.assertj.core.api.Assertions.assertThat;

class GlobalExceptionHandlerTests {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    void shouldHandleBadCredentialsException() {
        ProblemDetail pd = handler.handleBadCredentials(new BadCredentialsException("bad credentials"));
        assertThat(pd.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
        assertThat(pd.getDetail()).isEqualTo("Invalid credentials provided");
    }

    @Test
    void shouldHandleAccessDeniedException() {
        ProblemDetail pd = handler.handleAccessDenied(new AccessDeniedException("access denied"));
        assertThat(pd.getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
        assertThat(pd.getDetail()).isEqualTo("Access is denied");
    }

    @Test
    void shouldHandleRestClientException() {
        ProblemDetail pd = handler.handleRestClient(new RestClientException("upstream down"));
        assertThat(pd.getStatus()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE.value());
        assertThat(pd.getDetail()).isEqualTo("Authentication upstream service is unavailable");
    }

    @Test
    void shouldHandleGeneralException() {
        ProblemDetail pd = handler.handleGeneral(new RuntimeException("general failure"));
        assertThat(pd.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.value());
        assertThat(pd.getDetail()).isEqualTo("An unexpected server error occurred");
    }
}
