package com.lycos.aadsecuritydemo.security.config;

import com.lycos.aadsecuritydemo.security.filters.EasyAuthFilter;
import com.lycos.aadsecuritydemo.security.filters.PreAuthFilter;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class EasyAuthConfiguration implements AuthConfiguration {

    private final PreAuthFilter easyAuthFilter;

    public EasyAuthConfiguration(EasyAuthFilter easyAuthFilter) {
        this.easyAuthFilter = easyAuthFilter;
    }

    @Override
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        return http
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .securityContext(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .addFilterBefore(easyAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .build();
    }
}
