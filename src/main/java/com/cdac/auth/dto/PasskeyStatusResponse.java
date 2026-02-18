package com.cdac.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PasskeyStatusResponse {
    private Boolean enabled; // Passwordless login enabled
    private Boolean twoFactorEnabled; // 2FA with passkey enabled
    private Integer passkeyCount;
    private List<PasskeyInfo> passkeys;
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PasskeyInfo {
        private String credentialId;
        private String deviceName;
        private String createdAt;
        private String lastUsedAt;
    }
}
