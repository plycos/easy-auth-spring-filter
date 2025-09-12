package com.lycos.aadsecuritydemo.security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@Configuration
@Profile("!dev")
@EnableMethodSecurity
public class MethodSecurityConfig {
}
