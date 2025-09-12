package com.lycos.aadsecuritydemo.security.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

public interface AuthConfiguration {
    SecurityFilterChain configure(HttpSecurity http) throws Exception;
}
