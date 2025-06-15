package com.xt.bo.rsademo.Controller.Encryption;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Cipher;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@RestController
@Slf4j
@RequestMapping("/apiv2")
public class EncryptionV2Controller {

    @PostMapping("/secure")
    public ResponseEntity<Map<String, String>> receiveEncrypted(@RequestBody EncryptedPayload payload) throws Exception {
        String decryptedRequest = decrypt(payload.getEncrypted());

        // Process the decrypted message
        String responseMessage = "Server received: " + decryptedRequest;
        log.info(responseMessage);
        // Encrypt response with preloaded client public key
        String encryptedResponse = encryptForClient(responseMessage);

        Map<String, String> response = new HashMap<>();
        response.put("encryptedResponse", encryptedResponse);
        return ResponseEntity.ok(response);
    }

    private String decrypt(String encryptedBase64) throws Exception {
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedBase64);
        PrivateKey privateKey = loadPrivateKey("private.pem");

//      Same algorithm as client using RSA-OAEP
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(encryptedBytes));
    }

    private String encryptForClient(String message) throws Exception {
        PublicKey clientPublicKey = loadPublicKey("client-public.pem");

//      Same algorithm as client using RSA-OAEP
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private PrivateKey loadPrivateKey(String fileName) throws Exception {
        String key = Files.readString(Path.of("src/main/resources/" + fileName));
        key = key.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] keyBytes = Base64.getDecoder().decode(key);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    private PublicKey loadPublicKey(String fileName) throws Exception {
        String key = Files.readString(Path.of("src/main/resources/" + fileName));
        key = key.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] keyBytes = Base64.getDecoder().decode(key);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static class EncryptedPayload {
        private String encrypted;

        public String getEncrypted() {
            return encrypted;
        }

        public void setEncrypted(String encrypted) {
            this.encrypted = encrypted;
        }
    }
}


