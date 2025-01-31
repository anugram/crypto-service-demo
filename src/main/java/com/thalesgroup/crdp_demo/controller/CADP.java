package com.thalesgroup.crdp_demo.controller;

import java.nio.charset.StandardCharsets;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.apache.commons.codec.binary.Base64;

import com.clientmanagement.CipherTextData;
import com.clientmanagement.ClientManagementProvider;
import com.clientmanagement.RegisterClientParameters;
import com.clientmanagement.policy.CryptoManager;
import com.thalesgroup.crdp_demo.model.Payload;

/**
 * @author CipherTrust.io
 *
 */
@RestController
public class CADP {

    @Value("${KEY_MANAGER_HOST:10.10.10.10}")
    private String cmIP;

    @Value("${REGISTRATION_TOKEN_CADP:REG_TOKEN}")
    private String regtokenCADPApp;

    @Value("${PROTECTION_POLICY:PPName}")
    private String protectionPolicy;

    @PostMapping("/api/cadp/protect")
	public Payload protect(@RequestBody Payload bean) {
        Payload response = new Payload();

        RegisterClientParameters registerClientParams = new RegisterClientParameters.Builder(
            cmIP,
            regtokenCADPApp.toCharArray()).build();

        //creates provider object.
        ClientManagementProvider clientManagementProvider;
        try {
            clientManagementProvider = new ClientManagementProvider(registerClientParams);
            clientManagementProvider.addProvider();

            CipherTextData protectedData = CryptoManager.protect(
                bean.getData().getBytes(),
                protectionPolicy);
            response.setData(new String(protectedData.getCipherText(), StandardCharsets.UTF_8));
        } catch (ClassNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return response;
	}

    @PostMapping("/api/cadp/reveal")
	public Payload reveal(
        @RequestHeader("Authorization") String auth,
        @RequestBody Payload bean) {

        String pair=new String(Base64.decodeBase64(auth.substring(6)));
        String userName=pair.split(":")[0];
		Payload response = new Payload();

        RegisterClientParameters registerClientParams = new RegisterClientParameters.Builder(
            cmIP,
            regtokenCADPApp.toCharArray()).build();

        //creates provider object.
        ClientManagementProvider clientManagementProvider;
        try {
            clientManagementProvider = new ClientManagementProvider(registerClientParams);
            clientManagementProvider.addProvider();

            CipherTextData cipherTextData = new CipherTextData();
            cipherTextData.setCipherText(bean.getData().getBytes());

            byte[] revealedData = CryptoManager.reveal(
                cipherTextData,
                protectionPolicy,
                userName);
            response.setData(new String(revealedData, StandardCharsets.UTF_8));
        } catch (ClassNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return response;
	}
}
