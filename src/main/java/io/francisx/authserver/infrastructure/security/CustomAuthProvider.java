package io.francisx.authserver.infrastructure.security;

import io.francisx.authserver.domain.dto.response.UserResponse;
import io.francisx.authserver.infrastructure.client.UserClient;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;

import java.util.Collections;
import java.util.List;

@RequiredArgsConstructor
@Component
public class CustomAuthProvider implements AuthenticationProvider {

    private static final String DUMMY_HASH = "$2a$10$wO8lEcm8V5v3z/p6d6O.z.QeS7uN6L3QOa8pZlS7k2r1M2q4k7Z0e";

    private final UserClient userClient;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String presentedPassword = authentication.getCredentials() != null ? authentication.getCredentials().toString() : "";

        UserResponse user;
        try {
            user = userClient.findByUsername(username);
        } catch (HttpClientErrorException.NotFound ex) {
            user = null;
        } catch (RestClientException ex) {
            throw new BadCredentialsException("Authentication service unavailable");
        }

        if (user == null || user.password() == null) {
            passwordEncoder.matches(presentedPassword, DUMMY_HASH);
            throw new BadCredentialsException("Bad credentials");
        }

        if (!passwordEncoder.matches(presentedPassword, user.password())) {
            throw new BadCredentialsException("Bad credentials");
        }

        List<String> roles = user.role() != null ? user.role() : Collections.emptyList();
        var authorities = roles.stream()
                .map(SimpleGrantedAuthority::new)
                .toList();

        return new UsernamePasswordAuthenticationToken(user.username(), null, authorities);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
