package br.com.fiap.wsrest.covidwebapi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Classe inicial - Spring Boot Application que inicia a aplica��o Spring Boot atrav�s do m�todo Main
 * 
 * @author Carlos Eduardo Roque da Silva
 *
 */
@SpringBootApplication
public class CovidWebApiApplication {

	public static void main(String[] args) {
		SpringApplication.run(CovidWebApiApplication.class, args);
	}
}
