package com.lycos.aadsecuritydemo.security.providers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.lycos.aadsecuritydemo.security.domain.AuthenticatedUser;
import com.lycos.aadsecuritydemo.security.domain.UserProvider;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class EasyAuthUserProvider implements UserProvider {
    private static final Logger log = LoggerFactory.getLogger(EasyAuthUserProvider.class);

    private static final String AAD_ACCESS_TOKEN = "X-MS-TOKEN-AAD-ACCESS-TOKEN";
    private static final String PRINCIPAL_HEADER = "X-MS-CLIENT-PRINCIPAL";

    private static final String[] USERNAME_CLAIMS = new String[]{
            "preferred_username"
    };

    private static final Set<String> ROLE_CLAIM_TYPES = Set.of(
            "roles",
            "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
    );

    private static final Base64.Decoder B64_URL = Base64.getUrlDecoder();
    private static final Base64.Decoder B64_STD = Base64.getDecoder();

    private final ObjectMapper mapper;

    public EasyAuthUserProvider(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public Optional<AuthenticatedUser> provide(HttpServletRequest request) {
        String aadAccessToken = request.getHeader(AAD_ACCESS_TOKEN);
        String principalHeader = request.getHeader(PRINCIPAL_HEADER);

        if (principalHeader == null || principalHeader.isBlank() || aadAccessToken == null || aadAccessToken.isBlank()) {
            return Optional.empty();
        }

        String username = extractUsername(aadAccessToken);
        Set<String> roles = extractRoles(principalHeader);

        if (roles.isEmpty()) {
            log.debug("No roles found in client principal header");
        }

        return Optional.of(new AuthenticatedUser(username, roles));
    }

    private String extractUsername(String header) {
        try {
            String[] chunks = header.split("\\.");
            if (chunks.length < 2) {
                log.warn("Invalid JWT format in AAD access token: {}", header);
                return "system";
            }

            String tokenBody = new String(B64_URL.decode(chunks[1]));
            JsonNode root = mapper.readTree(tokenBody);

            for (String claim : USERNAME_CLAIMS) {
                if (root.has(claim)) {
                    return root.get(claim).asText();
                }
            }

            return "system";
        } catch (Exception e) {
            return "system";
        }
    }

    private Set<String> extractRoles(String header) {
        try {
            String json = new String(B64_STD.decode(header), StandardCharsets.UTF_8);
            JsonNode root = mapper.readTree(json);
            JsonNode claims = root.path("claims");
            if (!claims.isArray()) {
                return Collections.emptySet();
            }

            return claims.valueStream()
                    .filter(claim -> ROLE_CLAIM_TYPES.contains(claim.path("typ").asText()))
                    .map(claim -> claim.path("val").asText())
                    .filter(val -> val != null && !val.isBlank())
                    .collect(Collectors.toUnmodifiableSet());
        } catch (Exception e) {
            log.warn("Failed to parse roles from client principal header: {}", e.getMessage());
            log.debug("Client principal parsing error", e);
            return Collections.emptySet();
        }
    }
}
