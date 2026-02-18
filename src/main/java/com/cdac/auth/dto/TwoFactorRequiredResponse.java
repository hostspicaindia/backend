package com.cdac.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TwoFactorRequiredResponse {
    private String tempToken; // Temporary token for 2FA verification
    private Boolean twoFactorRequired;
    private String message;
}
