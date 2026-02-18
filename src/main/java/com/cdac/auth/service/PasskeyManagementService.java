package com.cdac.auth.service;

import com.cdac.auth.dto.PasskeyStatusResponse;
import com.cdac.auth.entity.PasskeyCredential;
import com.cdac.auth.entity.User;
import com.cdac.auth.exception.AuthenticationException;
import com.cdac.auth.repository.PasskeyCredentialRepository;
import com.cdac.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class PasskeyManagementService {
    
    private final UserRepository userRepository;
    private final PasskeyCredentialRepository credentialRepository;
    
    @Transactional(readOnly = true)
    public PasskeyStatusResponse getPasskeyStatus(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new AuthenticationException("User not found"));
        
        var passkeys = user.getCredentials().stream()
                .map(cred -> PasskeyStatusResponse.PasskeyInfo.builder()
                        .credentialId(cred.getCredentialId())
                        .deviceName(cred.getDeviceName())
                        .createdAt(cred.getCreatedAt().toString())
                        .lastUsedAt(cred.getLastUsedAt().toString())
                        .build())
                .collect(Collectors.toList());
        
        return PasskeyStatusResponse.builder()
                .enabled(user.getPasskeyEnabled())
                .twoFactorEnabled(user.getTwoFactorEnabled())
                .passkeyCount(user.getCredentials().size())
                .passkeys(passkeys)
                .build();
    }
    
    @Transactional
    public void enablePasskey(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new AuthenticationException("User not found"));
        
        if (user.getCredentials().isEmpty()) {
            throw new AuthenticationException("No passkeys registered. Please add a passkey first.");
        }
        
        user.setPasskeyEnabled(true);
        userRepository.save(user);
    }
    
    @Transactional
    public void disablePasskey(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new AuthenticationException("User not found"));
        
        user.setPasskeyEnabled(false);
        userRepository.save(user);
    }
    
    @Transactional
    public void deletePasskey(String email, String credentialId) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new AuthenticationException("User not found"));
        
        PasskeyCredential credential = credentialRepository.findByCredentialId(credentialId)
                .filter(cred -> cred.getUser().getId().equals(user.getId()))
                .orElseThrow(() -> new AuthenticationException("Passkey not found"));
        
        // Delete the credential
        credentialRepository.delete(credential);
        credentialRepository.flush(); // Force the delete to happen now
        
        // Check remaining passkeys count
        long remainingCount = credentialRepository.countByUserId(user.getId());
        
        // Disable passwordless and 2FA if no passkeys left
        if (remainingCount == 0) {
            user.setPasskeyEnabled(false);
            user.setTwoFactorEnabled(false);
            userRepository.save(user);
        }
    }

    @Transactional
    public void enableTwoFactor(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new AuthenticationException("User not found"));
        
        if (user.getCredentials().isEmpty()) {
            throw new AuthenticationException("No passkeys registered. Please add a passkey first.");
        }
        
        user.setTwoFactorEnabled(true);
        userRepository.save(user);
    }
    
    @Transactional
    public void disableTwoFactor(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new AuthenticationException("User not found"));
        
        user.setTwoFactorEnabled(false);
        userRepository.save(user);
    }
}
