package com.refactorizando.configclient;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@SpringBootApplication
public class ClientApplication {

	public static void main(String[] args) {
		SpringApplication.run(ClientApplication.class, args);
	}


	@Value("${properties.hello}")
	private String gitProperty;

	@Value("${client.property}")
	private String vaultProperty;

	@GetMapping("/property")
	public ResponseEntity<String> getProperty() {
		return ResponseEntity.ok(gitProperty + " " + vaultProperty);
	}
}
