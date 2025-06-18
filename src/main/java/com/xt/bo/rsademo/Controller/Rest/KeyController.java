package com.xt.bo.rsademo.Controller.Rest;

import com.xt.bo.rsademo.Payload.DeviceRequest;
import com.xt.bo.rsademo.Service.KeyService;
import com.xt.bo.rsademo.Service.RsaKeyService;
import com.xt.bo.rsademo.models.Response.KeyResponse;
import jakarta.annotation.Resource;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.nio.file.Files;
import java.nio.file.Path;

@RestController
@RequiredArgsConstructor
public class KeyController {
    private final KeyService keyService;
    private final RsaKeyService rsaKeyService;

    @PostMapping("/key")
    public ResponseEntity<?> getEncryptedPayload(@RequestBody DeviceRequest request) {
        try {
            KeyResponse response= rsaKeyService.generateAndSaveRsaKeyPair(request);
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error generating keys: " + e.getMessage());
        }
    }



}
