package com.xt.bo.rsademo.Service;

import com.xt.bo.rsademo.Payload.DeviceRequest;
import com.xt.bo.rsademo.models.Response.KeyResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class RsaKeyService {
    private final KeyService keyService;

    public KeyResponse generateAndSaveRsaKeyPair(DeviceRequest request) throws Exception {
        KeyResponse response = new KeyResponse();
        // Generate the key pair
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048); // Equivalent to rsa_keygen_bits:2048
        KeyPair pair = generator.generateKeyPair();

        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

        byte[] publicKeyBytes = publicKey.getEncoded();
        byte[] privateKeyBytes = privateKey.getEncoded();

        // Save keys to files in PEM format
        String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKeyBytes);
        String pemPublic = "-----BEGIN PUBLIC KEY-----\n" +
                publicKeyBase64 + "\n" +
                "-----END PUBLIC KEY-----\n";
        String privateKeyBase64 = Base64.getEncoder().encodeToString(privateKeyBytes);
        String pemPrivate = "-----BEGIN PRIVATE KEY-----\n" +
                privateKeyBase64 + "\n" +
                "-----END  PRIVATE KEY-----\n";

        String key = Files.readString(Path.of("src/main/resources/public.pem"));
        response.setClientPrivateKey(pemPrivate);
        response.setClientPublicKey(pemPublic);
        response.setServerPublicKey(key);
        keyService.saveKey(pemPublic,pemPrivate,request);
        return response;
    }
}
