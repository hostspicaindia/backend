package com.cdac.auth.repository;

import com.cdac.auth.entity.PasskeyCredential;
import com.cdac.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface PasskeyCredentialRepository extends JpaRepository<PasskeyCredential, Long> {
    
    Optional<PasskeyCredential> findByCredentialId(String credentialId);
    
    List<PasskeyCredential> findByUser(User user);
    
    long countByUserId(Long userId);
    
    boolean existsByCredentialId(String credentialId);
}
