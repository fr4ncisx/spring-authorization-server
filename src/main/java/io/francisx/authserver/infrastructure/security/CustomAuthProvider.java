package io.francisx.authserver.infrastructure.security;

import io.francisx.authserver.domain.dto.response.UserResponse;
import io.francisx.authserver.infrastructure.client.CustomFeignClient;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
public class CustomAuthProvider implements AuthenticationProvider {

    private final CustomFeignClient feignClient;

    /**
     * This verifies Authentication from UI login with DB
     * checks if password matches
     * @param authentication the authentication request object.
     * @return authenticated username
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UserResponse user = feignClient.findByUsername(authentication.getName());

        PasswordEncoder encoder = new BCryptPasswordEncoder();

        boolean passwordMatch = encoder.matches(authentication.getCredentials().toString()
                , user.getPassword());
        if(!passwordMatch){
            throw new BadCredentialsException("Invalid password");
        }
        var authorities = user.getRole().stream()
                .map(SimpleGrantedAuthority::new)
                .toList();
        return new UsernamePasswordAuthenticationToken(user.getUsername(),
                null, authorities);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
