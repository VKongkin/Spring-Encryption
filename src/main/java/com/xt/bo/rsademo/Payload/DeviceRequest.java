package com.xt.bo.rsademo.Payload;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class DeviceRequest {
    private String clientSecret;
    private String deviceId;
}
