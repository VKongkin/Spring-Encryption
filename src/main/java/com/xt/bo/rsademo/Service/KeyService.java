package com.xt.bo.rsademo.Service;

import com.xt.bo.rsademo.Payload.DeviceRequest;

public interface KeyService {
    void saveKey(String publicKeyBytes, String privateKeyBytes, DeviceRequest request);
}
