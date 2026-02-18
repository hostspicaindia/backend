package com.cdac.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Main application class for Passwordless Authentication Backend
 * 
 * This application provides WebAuthn/FIDO2 passwordless authentication services
 * for enterprise applications including WebMail and GitLab.
 */
@SpringBootApplication
public class PasswordlessAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(PasswordlessAuthApplication.class, args);
    }
}
