package com.cdac.auth.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * PasskeyCredential entity storing WebAuthn credential data
 * 
 * Stores public key and metadata for FIDO2 authenticators
 */
@Entity
@Table(name = "passkey_credentials")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PasskeyCredential {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, columnDefinition = "TEXT")
    private String credentialId; // Base64URL encoded

    @Column(nullable = false, columnDefinition = "TEXT")
    private String publicKey; // Base64URL encoded COSE key

    @Column(nullable = false)
    private Long signatureCounter;

    @Column(columnDefinition = "TEXT")
    private String transports; // Comma-separated: usb,nfc,ble,internal

    @Column(nullable = false)
    private String aaguid; // Authenticator Attestation GUID

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private LocalDateTime lastUsedAt;

    @Column
    private String deviceName; // Optional friendly name

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        lastUsedAt = LocalDateTime.now();
    }
}
