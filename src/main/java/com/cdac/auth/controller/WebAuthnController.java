package com.cdac.auth.controller;

import com.cdac.auth.dto.*;
import com.cdac.auth.service.WebAuthnService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * REST controller for WebAuthn operations
 * 
 * Endpoints:
 * - POST /webauthn/register/start - Initiate passkey registration
 * - POST /webauthn/register/finish - Complete passkey registration
 * - POST /webauthn/authenticate/start - Initiate authentication
 * - POST /webauthn/authenticate/finish - Complete authentication
 */
@RestController
@RequestMapping("/webauthn")
@RequiredArgsConstructor
@CrossOrigin(origins = "${cors.allowed-origins}")
public class WebAuthnController {
    
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(WebAuthnController.class);

    private final WebAuthnService webAuthnService;

    /**
     * Start registration flow
     * For logged-in users adding a passkey
     */
    @PostMapping("/register/start")
    public ResponseEntity<Object> startRegistration(Authentication authentication) {
        String email = authentication.getName();
        log.info("POST /webauthn/register/start - email: {}", email);
        Object options = webAuthnService.startRegistrationForUser(email);
        return ResponseEntity.ok(options);
    }

    /**
     * Finish registration flow
     * Verifies attestation and stores credential
     */
    @PostMapping("/register/finish")
    public ResponseEntity<Void> finishRegistration(
            Authentication authentication,
            @RequestBody Map<String, Object> request) {
        String email = authentication.getName();
        String deviceName = (String) request.getOrDefault("deviceName", "Security Key");
        log.info("POST /webauthn/register/finish - email: {}, deviceName: {}", email, deviceName);
        webAuthnService.finishRegistrationForUser(email, request.get("credential"), deviceName);
        return ResponseEntity.ok().build();
    }

    /**
     * Start authentication flow
     * Generates challenge for credential assertion
     * Only works if user has passwordless enabled
     */
    @PostMapping("/authenticate/start")
    public ResponseEntity<Object> startAuthentication(@RequestBody AuthenticationStartRequest request) {
        log.info("POST /webauthn/authenticate/start - email: {}", request.getUsername());
        Object options = webAuthnService.startAuthentication(request);
        return ResponseEntity.ok(options);
    }

    /**
     * Finish authentication flow
     * Verifies assertion and returns JWT token
     */
    @PostMapping("/authenticate/finish")
    public ResponseEntity<AuthenticationResponse> finishAuthentication(@RequestBody AuthenticationFinishRequest request) {
        log.info("POST /webauthn/authenticate/finish");
        AuthenticationResponse response = webAuthnService.finishAuthentication(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Start 2FA verification
     * Generates challenge for 2FA passkey verification
     */
    @PostMapping("/2fa/start")
    public ResponseEntity<Object> start2FA(@RequestBody Map<String, String> request) {
        String tempToken = request.get("tempToken");
        log.info("POST /webauthn/2fa/start");
        Object options = webAuthnService.start2FA(tempToken);
        return ResponseEntity.ok(options);
    }

    /**
     * Finish 2FA verification
     * Verifies passkey and returns full JWT token
     */
    @PostMapping("/2fa/verify")
    public ResponseEntity<AuthenticationResponse> verify2FA(@RequestBody TwoFactorVerifyRequest request) {
        log.info("POST /webauthn/2fa/verify");
        AuthenticationResponse response = webAuthnService.verify2FA(request);
        return ResponseEntity.ok(response);
    }
}
