package com.Spring.PKCE.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class SecurityController {

    @GetMapping
    public ResponseEntity<String> getProtectedResource(Authentication authentication) {
        String username = (authentication != null) ? authentication.getName() : "anonymous";
        return ResponseEntity.ok("Protected resource accessed by: " + username);
    }
}
