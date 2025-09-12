package com.lycos.aadsecuritydemo.security.filters;

import com.lycos.aadsecuritydemo.security.domain.AuthenticatedUser;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public abstract class PreAuthFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        extractUser(request).ifPresent(this::setSecurityContext);
        filterChain.doFilter(request, response);
    }

    protected abstract Optional<AuthenticatedUser> extractUser(HttpServletRequest request);

    private void setSecurityContext(AuthenticatedUser user) {
        List<GrantedAuthority> authorities = user.roles().stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role)).collect(Collectors.toList());

        AbstractAuthenticationToken authentication = new PreAuthenticatedAuthenticationToken(user.username(), null, authorities);

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
