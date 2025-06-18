package com.xt.bo.rsademo.Payload;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class KeyRequest {
    private String publicKey;
    private String privateKey;
    private String clientSecret;
    private String deviceId;
}
