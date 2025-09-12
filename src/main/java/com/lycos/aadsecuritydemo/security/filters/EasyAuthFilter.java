package com.lycos.aadsecuritydemo.security.filters;

import com.lycos.aadsecuritydemo.security.domain.AuthenticatedUser;
import com.lycos.aadsecuritydemo.security.domain.UserProvider;
import com.lycos.aadsecuritydemo.security.providers.EasyAuthUserProvider;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class EasyAuthFilter extends PreAuthFilter {

    private final UserProvider easyAuthUserProvider;

    public EasyAuthFilter(EasyAuthUserProvider easyAuthUserProvider) {
        this.easyAuthUserProvider = easyAuthUserProvider;
    }

    @Override
    protected Optional<AuthenticatedUser> extractUser(HttpServletRequest request) {
        return easyAuthUserProvider.provide(request);
    }
}
