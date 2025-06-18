package com.xt.bo.rsademo.Payload;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class HybridPayload {
    private String encryptedKey;
    private String iv;
    private String encryptedData;
}
