package com.elasticjee;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;

/**
 * @author yangck
 */
@SpringBootApplication
@EnableOAuth2Sso
public class SocialApplication {
    public static void main(String[] args) {
        SpringApplication.run(SocialApplication.class, args);
    }
}
