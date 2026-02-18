package com.cdac.auth.controller;

import com.cdac.auth.dto.PasskeyStatusResponse;
import com.cdac.auth.service.PasskeyManagementService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/**
 * Passkey management controller
 * Handles enabling/disabling passwordless login
 */
@RestController
@RequestMapping("/passkey")
@RequiredArgsConstructor
@CrossOrigin(origins = "${cors.allowed-origins}")
public class PasskeyController {
    
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(PasskeyController.class);
    
    private final PasskeyManagementService passkeyService;
    
    /**
     * Get passkey status for user
     */
    @GetMapping("/status")
    public ResponseEntity<PasskeyStatusResponse> getStatus(Authentication authentication) {
        String email = authentication.getName();
        log.info("GET /passkey/status - email: {}", email);
        PasskeyStatusResponse response = passkeyService.getPasskeyStatus(email);
        return ResponseEntity.ok(response);
    }
    
    /**
     * Enable passwordless login for user
     */
    @PostMapping("/enable")
    public ResponseEntity<Void> enable(Authentication authentication) {
        String email = authentication.getName();
        log.info("POST /passkey/enable - email: {}", email);
        passkeyService.enablePasskey(email);
        return ResponseEntity.ok().build();
    }
    
    /**
     * Disable passwordless login for user
     */
    @PostMapping("/disable")
    public ResponseEntity<Void> disable(Authentication authentication) {
        String email = authentication.getName();
        log.info("POST /passkey/disable - email: {}", email);
        passkeyService.disablePasskey(email);
        return ResponseEntity.ok().build();
    }
    
    /**
     * Delete a specific passkey
     */
    @DeleteMapping("/{credentialId}")
    public ResponseEntity<Void> deletePasskey(
            Authentication authentication,
            @PathVariable String credentialId) {
        String email = authentication.getName();
        log.info("DELETE /passkey/{} - email: {}", credentialId, email);
        passkeyService.deletePasskey(email, credentialId);
        return ResponseEntity.ok().build();
    }

    /**
     * Enable 2FA with passkey
     */
    @PostMapping("/2fa/enable")
    public ResponseEntity<Void> enableTwoFactor(Authentication authentication) {
        String email = authentication.getName();
        log.info("POST /passkey/2fa/enable - email: {}", email);
        passkeyService.enableTwoFactor(email);
        return ResponseEntity.ok().build();
    }
    
    /**
     * Disable 2FA with passkey
     */
    @PostMapping("/2fa/disable")
    public ResponseEntity<Void> disableTwoFactor(Authentication authentication) {
        String email = authentication.getName();
        log.info("POST /passkey/2fa/disable - email: {}", email);
        passkeyService.disableTwoFactor(email);
        return ResponseEntity.ok().build();
    }
}
