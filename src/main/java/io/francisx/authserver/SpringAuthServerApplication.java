package io.francisx.authserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class SpringAuthServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(SpringAuthServerApplication.class, args);
    }
}