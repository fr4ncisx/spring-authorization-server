package io.francisx.authserver.infrastructure.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

@Service
public class TokenService {

    @Value("${security.token.uri}")
    private String tokenUri;
    @Value("${security.secret-key}")
    private String clientSecretKey;
    @Value("${oauth2.clientid.service-client}")
    private String clientIdServiceClient;
    @Value("${oauth2.client.scope}")
    private String clientScope;

    /**
     * This method calls {@code http://auth-service/oauth2/token} to create an internal token
     * with your customized scope
     * @return Token without starting with Bearer
     */
    public String getClientCredentialsToken() {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.setBasicAuth(clientIdServiceClient, clientSecretKey);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "client_credentials");
        params.add("scope", clientScope);

        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(params, headers);

        ResponseEntity<Map<String, Object>> response = restTemplate.exchange(tokenUri, HttpMethod.POST, entity,
                new ParameterizedTypeReference<>() {});

        return Optional.ofNullable(response.getBody())
                .orElseThrow(() -> new HttpServerErrorException(HttpStatus.BAD_REQUEST, "Token Response Failed"))
                .get("access_token").toString();
    }

}
