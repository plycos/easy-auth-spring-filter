package com.lycos.aadsecuritydemo.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth-test")
public class AuthTestController {

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, Object> test() {
        Map<String, Object> map = new HashMap<>();
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        map.put("username", auth.getPrincipal().toString());
        map.put("roles", auth.getAuthorities());
        return map;
    }
}
