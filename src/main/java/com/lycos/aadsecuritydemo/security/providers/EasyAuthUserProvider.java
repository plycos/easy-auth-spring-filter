package com.lycos.aadsecuritydemo.security.providers;

import com.lycos.aadsecuritydemo.security.domain.AuthenticatedUser;
import com.lycos.aadsecuritydemo.security.domain.UserProvider;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.Set;

@Component
public class EasyAuthUserProvider implements UserProvider {

    @Override
    public Optional<AuthenticatedUser> provide(HttpServletRequest request) {
        String userPrincipal = request.getHeader("X-MS-CLIENT-PRINCIPAL");
        String userRoles = request.getHeader("X-MS-CLIENT-PRINCIPAL-ROLES");
        return Optional.of(new AuthenticatedUser("system", Set.of("USER", "ADMIN")));
    }
}
