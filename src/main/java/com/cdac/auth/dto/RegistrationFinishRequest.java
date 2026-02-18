package com.cdac.auth.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RegistrationFinishRequest {
    private String username;
    private Object credential; // PublicKeyCredential from browser
}
