package com.lycos.aadsecuritydemo.security.domain;

import java.util.Set;

public record AuthenticatedUser(String username, Set<String> roles) {

}
