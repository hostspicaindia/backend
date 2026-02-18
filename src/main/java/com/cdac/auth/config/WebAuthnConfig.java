package com.cdac.auth.config;

import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * WebAuthn configuration using Yubico library
 * 
 * Configures Relying Party identity and origin validation
 */
@Configuration
public class WebAuthnConfig {

    @Value("${webauthn.rp.id}")
    private String rpId;

    @Value("${webauthn.rp.name}")
    private String rpName;

    @Value("${webauthn.origin}")
    private String origins;

    @Bean
    public RelyingPartyIdentity relyingPartyIdentity() {
        return RelyingPartyIdentity.builder()
                .id(rpId)
                .name(rpName)
                .build();
    }

    @Bean
    public RelyingParty relyingParty(
            RelyingPartyIdentity rpIdentity,
            com.cdac.auth.service.CredentialRepository credentialRepository) {
        Set<String> allowedOrigins = Arrays.stream(origins.split(","))
                .map(String::trim)
                .collect(Collectors.toSet());
        
        return RelyingParty.builder()
                .identity(rpIdentity)
                .credentialRepository(credentialRepository)
                .origins(allowedOrigins)
                .build();
    }
}
