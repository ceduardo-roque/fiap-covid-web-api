package br.com.fiap.wsrest.covidwebapi.service;

import java.util.List;

import br.com.fiap.wsrest.covidwebapi.dto.RetornoGlobalDTO;
import br.com.fiap.wsrest.covidwebapi.dto.RetornoPaisDTO;

/**
 * Interface Service utilizada para manipula��o na Controller. Ela exp�e m�todos para consulta de dados da Covid-19 de pa�ses 
 * @author Carlos Eduardo Roque da Silva
 *
 */
public interface CovidWebApiPaisesService {

	List<RetornoPaisDTO> buscaSituacaoPaises(String paises, String de, String ate);
	RetornoPaisDTO buscaSituacaoEmUmPais(String pais, String de, String ate);
	RetornoGlobalDTO buscaSituacaoGlobais();
}
