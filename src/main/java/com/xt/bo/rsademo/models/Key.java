package com.xt.bo.rsademo.models;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
@Table(name = "key_tbl")
public class Key {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "public_key", columnDefinition = "TEXT")
    private String publicKey;
    @Column(name = "private_key", columnDefinition = "TEXT")
    private String privateKey;
    private String clientSecret;
    private String deviceId;
}
