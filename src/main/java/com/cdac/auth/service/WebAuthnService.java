package com.cdac.auth.service;

import com.cdac.auth.dto.*;
import com.cdac.auth.entity.PasskeyCredential;
import com.cdac.auth.entity.User;
import com.cdac.auth.exception.AuthenticationException;
import com.cdac.auth.exception.RegistrationException;
import com.cdac.auth.repository.PasskeyCredentialRepository;
import com.cdac.auth.repository.UserRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.webauthn.*;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Core WebAuthn service handling registration and authentication flows
 * 
 * Uses Yubico WebAuthn Server library for cryptographic operations
 */
@Service
@RequiredArgsConstructor
public class WebAuthnService {
    
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(WebAuthnService.class);

    private final RelyingParty relyingParty;
    private final UserRepository userRepository;
    private final PasskeyCredentialRepository credentialRepository;
    private final JwtService jwtService;
    private final ObjectMapper objectMapper;

    // In-memory storage for pending operations (use Redis in production)
    private final Map<String, PublicKeyCredentialCreationOptions> pendingRegistrations = new ConcurrentHashMap<>();
    private final Map<String, AssertionRequest> pendingAuthentications = new ConcurrentHashMap<>();

    /**
     * Start registration flow - generates challenge and options
     * For logged-in users adding a passkey
     */
    @Transactional
    public Object startRegistrationForUser(String email) {
        log.info("Starting passkey registration for logged-in user: {}", email);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RegistrationException("User not found"));

        // Generate user handle if not exists
        if (user.getUserHandle() == null) {
            byte[] userHandle = new byte[64];
            new SecureRandom().nextBytes(userHandle);
            user.setUserHandle(userHandle);
            userRepository.save(user);
        }

        UserIdentity userIdentity = UserIdentity.builder()
                .name(user.getUsername())
                .displayName(user.getDisplayName())
                .id(new ByteArray(user.getUserHandle()))
                .build();

        StartRegistrationOptions registrationOptions = StartRegistrationOptions.builder()
                .user(userIdentity)
                .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
                        .userVerification(UserVerificationRequirement.PREFERRED)
                        .residentKey(ResidentKeyRequirement.PREFERRED)
                        .build())
                .build();

        PublicKeyCredentialCreationOptions options = relyingParty.startRegistration(registrationOptions);

        // Store pending registration
        pendingRegistrations.put(user.getEmail(), options);

        log.debug("Generated registration options for user: {}", email);
        try {
            return options.toJson();
        } catch (Exception e) {
            throw new RegistrationException("Failed to generate registration options: " + e.getMessage());
        }
    }

    /**
     * Finish registration flow - verifies attestation and stores credential
     * For logged-in users
     */
    @Transactional
    public void finishRegistrationForUser(String email, Object credentialData, String deviceName) {
        log.info("Finishing passkey registration for user: {} with device name: {}", email, deviceName);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RegistrationException("User not found"));

        PublicKeyCredentialCreationOptions options = pendingRegistrations.remove(email);
        if (options == null) {
            throw new RegistrationException("No pending registration found");
        }

        try {
            // Parse credential from frontend
            String credentialJson = objectMapper.writeValueAsString(credentialData);
            PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> pkc =
                    PublicKeyCredential.parseRegistrationResponseJson(credentialJson);

            FinishRegistrationOptions finishOptions = FinishRegistrationOptions.builder()
                    .request(options)
                    .response(pkc)
                    .build();

            RegistrationResult result = relyingParty.finishRegistration(finishOptions);

            // Store credential
            PasskeyCredential credential = PasskeyCredential.builder()
                    .credentialId(result.getKeyId().getId().getBase64Url())
                    .publicKey(result.getPublicKeyCose().getBase64Url())
                    .signatureCounter(result.getSignatureCount())
                    .aaguid(result.getAaguid().getHex())
                    .user(user)
                    .deviceName(deviceName)
                    .build();

            credentialRepository.save(credential);

            log.info("Successfully registered passkey for user: {}", email);

        } catch (RegistrationFailedException | IOException e) {
            log.error("Passkey registration failed for user: {}", email, e);
            throw new RegistrationException("Registration verification failed: " + e.getMessage());
        }
    }

    /**
     * Start authentication flow - generates challenge
     */
    public Object startAuthentication(AuthenticationStartRequest request) {
        log.info("Starting authentication for user: {}", request.getUsername());

        // Find user and verify they have passwordless enabled
        User user = userRepository.findByEmail(request.getUsername())
                .orElseThrow(() -> new AuthenticationException("User not found"));
        
        if (!user.getPasskeyEnabled()) {
            throw new AuthenticationException("Passwordless login is not enabled for this user");
        }

        // Don't pass username to WebAuthn - let it work with credentials only
        StartAssertionOptions assertionOptions = StartAssertionOptions.builder()
                .userVerification(UserVerificationRequirement.PREFERRED)
                .build();

        AssertionRequest assertionRequest = relyingParty.startAssertion(assertionOptions);

        // Store pending authentication with email as key
        pendingAuthentications.put(request.getUsername(), assertionRequest);

        log.debug("Generated authentication challenge");
        try {
            return assertionRequest.toJson();
        } catch (Exception e) {
            throw new AuthenticationException("Failed to generate authentication challenge: " + e.getMessage());
        }
    }

    /**
     * Finish authentication flow - verifies assertion and creates session
     */
    @Transactional
    public AuthenticationResponse finishAuthentication(AuthenticationFinishRequest request) {
        log.info("Finishing authentication");

        try {
            // Parse credential from frontend
            String credentialJson = objectMapper.writeValueAsString(request.getCredential());
            PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> pkc =
                    PublicKeyCredential.parseAssertionResponseJson(credentialJson);

            // Find credential by ID
            JsonNode credNode = objectMapper.readTree(credentialJson);
            String credentialId = credNode.get("id").asText();
            
            PasskeyCredential credential = credentialRepository.findByCredentialId(credentialId)
                    .orElseThrow(() -> new AuthenticationException("Credential not found"));

            User user = credential.getUser();
            
            // Get pending authentication by email
            AssertionRequest assertionRequest = pendingAuthentications.remove(user.getEmail());
            
            if (assertionRequest == null) {
                throw new AuthenticationException("No pending authentication found. Please try again.");
            }

            FinishAssertionOptions finishOptions = FinishAssertionOptions.builder()
                    .request(assertionRequest)
                    .response(pkc)
                    .build();

            AssertionResult result = relyingParty.finishAssertion(finishOptions);

            if (!result.isSuccess()) {
                throw new AuthenticationException("Authentication failed");
            }

            // Update signature counter
            credential.setSignatureCounter(result.getSignatureCount());
            credential.setLastUsedAt(LocalDateTime.now());
            credentialRepository.save(credential);

            // Generate JWT token with email (not username)
            String token = jwtService.generateToken(user.getEmail());

            log.info("Successfully authenticated user: {}", user.getEmail());

            return AuthenticationResponse.builder()
                    .token(token)
                    .username(user.getUsername())
                    .email(user.getEmail())
                    .displayName(user.getDisplayName())
                    .build();

        } catch (AssertionFailedException | IOException e) {
            log.error("Authentication failed", e);
            throw new AuthenticationException("Authentication verification failed: " + e.getMessage());
        }
    }

    public Object start2FA(String tempToken) {
        log.info("Starting 2FA verification");
        
        try {
            // Extract email from temp token
            String tokenSubject = jwtService.extractUsername(tempToken);
            String email = tokenSubject.split(":2fa:")[0];
            
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new AuthenticationException("User not found"));
            
            if (!user.getTwoFactorEnabled()) {
                throw new AuthenticationException("2FA is not enabled for this user");
            }
            
            // Generate assertion request
            StartAssertionOptions assertionOptions = StartAssertionOptions.builder()
                    .userVerification(UserVerificationRequirement.REQUIRED)
                    .build();

            AssertionRequest assertionRequest = relyingParty.startAssertion(assertionOptions);
            
            // Store with temp token as key
            pendingAuthentications.put(tempToken, assertionRequest);
            
            return assertionRequest.toJson();
        } catch (Exception e) {
            log.error("Failed to start 2FA", e);
            throw new AuthenticationException("Failed to start 2FA: " + e.getMessage());
        }
    }
    
    @Transactional
    public AuthenticationResponse verify2FA(TwoFactorVerifyRequest request) {
        log.info("Verifying 2FA");
        
        try {
            // Extract email from temp token
            String tokenSubject = jwtService.extractUsername(request.getTempToken());
            String email = tokenSubject.split(":2fa:")[0];
            
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new AuthenticationException("User not found"));
            
            // Parse credential
            String credentialJson = objectMapper.writeValueAsString(request.getCredential());
            PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> pkc =
                    PublicKeyCredential.parseAssertionResponseJson(credentialJson);
            
            // Get pending authentication
            AssertionRequest assertionRequest = pendingAuthentications.remove(request.getTempToken());
            if (assertionRequest == null) {
                throw new AuthenticationException("No pending 2FA verification found");
            }
            
            // Verify assertion
            FinishAssertionOptions finishOptions = FinishAssertionOptions.builder()
                    .request(assertionRequest)
                    .response(pkc)
                    .build();

            AssertionResult result = relyingParty.finishAssertion(finishOptions);
            
            if (!result.isSuccess()) {
                throw new AuthenticationException("2FA verification failed");
            }
            
            // Find and update credential
            JsonNode credNode = objectMapper.readTree(credentialJson);
            String credentialId = credNode.get("id").asText();
            
            PasskeyCredential credential = credentialRepository.findByCredentialId(credentialId)
                    .orElseThrow(() -> new AuthenticationException("Credential not found"));
            
            credential.setSignatureCounter(result.getSignatureCount());
            credential.setLastUsedAt(LocalDateTime.now());
            credentialRepository.save(credential);
            
            // Generate full JWT token
            String token = jwtService.generateToken(user.getEmail());
            
            log.info("Successfully verified 2FA for user: {}", email);
            
            return AuthenticationResponse.builder()
                    .token(token)
                    .username(user.getUsername())
                    .email(user.getEmail())
                    .displayName(user.getDisplayName())
                    .build();
            
        } catch (AssertionFailedException | IOException e) {
            log.error("2FA verification failed", e);
            throw new AuthenticationException("2FA verification failed: " + e.getMessage());
        }
    }
}
