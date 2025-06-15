package com.xt.bo.rsademo.Controller.Encryption;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/apiv3")
public class EncryptionHybridController {

    @PostMapping("/secure")
    public ResponseEntity<Map<String, String>> secure(@RequestBody HybridPayload payload) throws Exception {
        // Step 1: Decrypt AES key with server private key
        byte[] encryptedKeyBytes = Base64.getDecoder().decode(payload.getEncryptedKey());
        PrivateKey privateKey = loadPrivateKey("private.pem");

        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] aesKey = rsaCipher.doFinal(encryptedKeyBytes);

        // Step 2: Decrypt payload using AES key and IV
        byte[] iv = Base64.getDecoder().decode(payload.getIv());
        byte[] encryptedData = Base64.getDecoder().decode(payload.getEncryptedData());

        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec aesKeySpec = new SecretKeySpec(aesKey, "AES");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKeySpec, new IvParameterSpec(iv));
        String decryptedMessage = new String(aesCipher.doFinal(encryptedData), StandardCharsets.UTF_8);

        // Step 3: Encrypt response with AES and return
        String responseText = "Server received: " + decryptedMessage;
        byte[] responseIv = new byte[16];
        new SecureRandom().nextBytes(responseIv);
        Cipher aesResponseCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesResponseCipher.init(Cipher.ENCRYPT_MODE, aesKeySpec, new IvParameterSpec(responseIv));
        byte[] encryptedResponse = aesResponseCipher.doFinal(responseText.getBytes(StandardCharsets.UTF_8));

        Map<String, String> res = new HashMap<>();
//        res.put("encryptedKey", payload.getEncryptedKey());
        res.put("iv", Base64.getEncoder().encodeToString(responseIv));
        res.put("encryptedData", Base64.getEncoder().encodeToString(encryptedResponse));

        return ResponseEntity.ok(res);
    }

    private PrivateKey loadPrivateKey(String fileName) throws Exception {
        String key = Files.readString(Path.of("src/main/resources/" + fileName));
        key = key.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] keyBytes = Base64.getDecoder().decode(key);
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }

    public static class HybridPayload {
        private String encryptedKey;
        private String iv;
        private String encryptedData;

        public String getEncryptedKey() { return encryptedKey; }
        public void setEncryptedKey(String encryptedKey) { this.encryptedKey = encryptedKey; }

        public String getIv() { return iv; }
        public void setIv(String iv) { this.iv = iv; }

        public String getEncryptedData() { return encryptedData; }
        public void setEncryptedData(String encryptedData) { this.encryptedData = encryptedData; }
    }
}



