package com.cdac.auth.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthenticationStartRequest {
    private String username; // Optional for usernameless flow
}
