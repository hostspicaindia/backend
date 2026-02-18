package com.cdac.auth.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * User entity representing application users
 */
@Entity
@Table(name = "users")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false, unique = true)
    private String email;
    
    @Column(nullable = false)
    private String password; // Hashed password

    @Column(unique = true)
    private byte[] userHandle; // WebAuthn user.id (nullable until passkey is added)

    @Column(nullable = false)
    private String displayName;
    
    @Column(nullable = false)
    @Builder.Default
    private Boolean passkeyEnabled = false; // Whether user has enabled passwordless login
    
    @Column(nullable = false)
    @Builder.Default
    private Boolean twoFactorEnabled = false; // Whether user has enabled 2FA with passkey

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<PasskeyCredential> credentials = new ArrayList<>();

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
