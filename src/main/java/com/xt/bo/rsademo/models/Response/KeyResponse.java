package com.xt.bo.rsademo.models.Response;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class KeyResponse {
    private String clientPublicKey;
    private String clientPrivateKey;
    private String serverPublicKey;
}
