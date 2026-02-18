package com.cdac.auth.controller;

import com.cdac.auth.dto.*;
import com.cdac.auth.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Traditional authentication controller
 * Handles email/password registration and login
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = "${cors.allowed-origins}")
public class AuthController {
    
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(AuthController.class);
    
    private final AuthService authService;
    
    /**
     * Register new user with email and password
     */
    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@Valid @RequestBody RegisterRequest request) {
        log.info("POST /auth/register - email: {}", request.getEmail());
        AuthenticationResponse response = authService.register(request);
        return ResponseEntity.ok(response);
    }
    
    /**
     * Login with email and password
     * May return 2FA challenge if enabled
     */
    @PostMapping("/login")
    public ResponseEntity<Object> login(@Valid @RequestBody LoginRequest request) {
        log.info("POST /auth/login - email: {}", request.getEmail());
        Object response = authService.login(request);
        return ResponseEntity.ok(response);
    }
}
