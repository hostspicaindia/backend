package com.cdac.auth.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthenticationFinishRequest {
    private Object credential; // PublicKeyCredential from browser
}
