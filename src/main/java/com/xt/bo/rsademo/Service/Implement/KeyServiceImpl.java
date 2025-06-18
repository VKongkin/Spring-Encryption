package com.xt.bo.rsademo.Service.Implement;

import com.xt.bo.rsademo.Payload.DeviceRequest;
import com.xt.bo.rsademo.Repository.KeyRepository;
import com.xt.bo.rsademo.Service.KeyService;
import com.xt.bo.rsademo.models.Key;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Base64;

@Service
@RequiredArgsConstructor
public class KeyServiceImpl implements KeyService {
    private final KeyRepository keyRepository;


    @Override
    public void saveKey(String publicKeyBytes, String privateKeyBytes, DeviceRequest request) {
//        String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKeyBytes);
//        String privateKeyBase64 = Base64.getEncoder().encodeToString(privateKeyBytes);

        Key key = new Key();
        key.setPublicKey(publicKeyBytes);
        key.setPrivateKey(privateKeyBytes);
        key.setClientSecret(request.getClientSecret());
        key.setDeviceId(request.getDeviceId());
        // Optionally set clientSecret and deviceId if available
        keyRepository.save(key);
    }
}
