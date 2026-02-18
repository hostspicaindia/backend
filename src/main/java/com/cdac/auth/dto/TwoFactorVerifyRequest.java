package com.cdac.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TwoFactorVerifyRequest {
    private String tempToken; // Temporary token from initial login
    private Object credential; // WebAuthn credential
}
