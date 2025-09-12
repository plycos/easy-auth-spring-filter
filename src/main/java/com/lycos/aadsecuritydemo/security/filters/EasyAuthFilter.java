package com.lycos.aadsecuritydemo.security.filters;

import com.lycos.aadsecuritydemo.security.domain.AuthenticatedUser;
import com.lycos.aadsecuritydemo.security.domain.UserProvider;
import com.lycos.aadsecuritydemo.security.providers.EasyAuthUserProvider;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class EasyAuthFilter extends PreAuthFilter {

    private final UserProvider userProvider;

    public EasyAuthFilter(EasyAuthUserProvider userProvider) {
        this.userProvider = userProvider;
    }

    @Override
    protected Optional<AuthenticatedUser> extractUser(HttpServletRequest request) {
        return userProvider.provide(request);
    }
}
