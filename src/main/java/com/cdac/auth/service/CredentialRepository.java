package com.cdac.auth.service;

import com.cdac.auth.entity.PasskeyCredential;
import com.cdac.auth.repository.PasskeyCredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Implementation of Yubico's CredentialRepository interface
 * 
 * Bridges WebAuthn library with our database layer
 */
@Component
@RequiredArgsConstructor
public class CredentialRepository implements com.yubico.webauthn.CredentialRepository {
    
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(CredentialRepository.class);

    private final PasskeyCredentialRepository passkeyCredentialRepository;
    private final com.cdac.auth.repository.UserRepository userRepository;

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        return userRepository.findByUsername(username)
                .map(user -> user.getCredentials().stream()
                        .map(cred -> {
                            try {
                                return PublicKeyCredentialDescriptor.builder()
                                        .id(ByteArray.fromBase64Url(cred.getCredentialId()))
                                        .build();
                            } catch (Exception e) {
                                log.error("Error parsing credential ID", e);
                                return null;
                            }
                        })
                        .filter(java.util.Objects::nonNull)
                        .collect(Collectors.toSet()))
                .orElse(Set.of());
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        return userRepository.findByUsername(username)
                .map(user -> new ByteArray(user.getUserHandle()));
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        return userRepository.findByUserHandle(userHandle.getBytes())
                .map(com.cdac.auth.entity.User::getUsername);
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        String credentialIdBase64 = credentialId.getBase64Url();
        
        return passkeyCredentialRepository.findByCredentialId(credentialIdBase64)
                .map(cred -> {
                    try {
                        return RegisteredCredential.builder()
                                .credentialId(credentialId)
                                .userHandle(userHandle)
                                .publicKeyCose(ByteArray.fromBase64Url(cred.getPublicKey()))
                                .signatureCount(cred.getSignatureCounter())
                                .build();
                    } catch (Exception e) {
                        log.error("Error parsing credential", e);
                        return null;
                    }
                });
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        String credentialIdBase64 = credentialId.getBase64Url();
        
        return passkeyCredentialRepository.findByCredentialId(credentialIdBase64)
                .map(cred -> {
                    try {
                        return RegisteredCredential.builder()
                                .credentialId(credentialId)
                                .userHandle(new ByteArray(cred.getUser().getUserHandle()))
                                .publicKeyCose(ByteArray.fromBase64Url(cred.getPublicKey()))
                                .signatureCount(cred.getSignatureCounter())
                                .build();
                    } catch (Exception e) {
                        log.error("Error parsing credential", e);
                        return null;
                    }
                })
                .filter(java.util.Objects::nonNull)
                .map(Set::of)
                .orElse(Set.of());
    }
}
