package com.xt.bo.rsademo.Payload;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class EncryptedPubKeyPayload {
    private String encrypted;
    private String clientPublicKey;
}
