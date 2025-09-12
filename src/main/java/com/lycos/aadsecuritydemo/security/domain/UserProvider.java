package com.lycos.aadsecuritydemo.security.domain;

import jakarta.servlet.http.HttpServletRequest;

import java.util.Optional;

public interface UserProvider {
    Optional<AuthenticatedUser> provide(HttpServletRequest request);
}
