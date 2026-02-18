package com.cdac.auth.service;

import com.cdac.auth.dto.*;
import com.cdac.auth.entity.User;
import com.cdac.auth.exception.AuthenticationException;
import com.cdac.auth.exception.RegistrationException;
import com.cdac.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Traditional authentication service
 * Handles email/password registration and login
 */
@Service
@RequiredArgsConstructor
public class AuthService {
    
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(AuthService.class);
    
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    
    @Transactional
    public AuthenticationResponse register(RegisterRequest request) {
        log.info("Registering user: {}", request.getEmail());
        
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RegistrationException("Email already registered");
        }
        
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RegistrationException("Username already taken");
        }
        
        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .displayName(request.getName())
                .passkeyEnabled(false)
                .build();
        
        user = userRepository.save(user);
        
        String token = jwtService.generateToken(user.getEmail());
        
        log.info("Successfully registered user: {}", request.getEmail());
        
        return AuthenticationResponse.builder()
                .token(token)
                .username(user.getUsername())
                .email(user.getEmail())
                .displayName(user.getDisplayName())
                .build();
    }
    
    @Transactional(readOnly = true)
    public Object login(LoginRequest request) {
        log.info("Logging in user: {}", request.getEmail());
        
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new AuthenticationException("Invalid email or password"));
        
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new AuthenticationException("Invalid email or password");
        }
        
        // Check if 2FA is enabled
        if (user.getTwoFactorEnabled() && !user.getCredentials().isEmpty()) {
            // Generate temporary token for 2FA
            String tempToken = jwtService.generateToken(user.getEmail() + ":2fa:" + System.currentTimeMillis());
            
            log.info("2FA required for user: {}", request.getEmail());
            
            return TwoFactorRequiredResponse.builder()
                    .tempToken(tempToken)
                    .twoFactorRequired(true)
                    .message("Two-factor authentication required")
                    .build();
        }
        
        String token = jwtService.generateToken(user.getEmail());
        
        log.info("Successfully logged in user: {}", request.getEmail());
        
        return AuthenticationResponse.builder()
                .token(token)
                .username(user.getUsername())
                .email(user.getEmail())
                .displayName(user.getDisplayName())
                .build();
    }
}
