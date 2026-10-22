package com.dpiengine.api;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(ApiProperties.class)
public class DpiApiApplication {
    public static void main(String[] args) { SpringApplication.run(DpiApiApplication.class, args); }
}
