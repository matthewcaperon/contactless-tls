/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.microexpert.cltls.samples.desktopsample;

import com.microexpert.cltls.core.Smartcard;
import com.microexpert.cltls.core.SmartcardTlsClient;
import com.microexpert.cltls.smartcards.anycard.AnyCard;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import org.spongycastle.crypto.tls.DefaultTlsClient;
import org.spongycastle.crypto.tls.TlsClientProtocol;

/**
 *
 * @author John
 */
public class DesktopClient {

    public static void main(String[] args) throws IOException, CertificateEncodingException {
        
        // Trusted Certificate Authorities 
        // Replace with you own CA certificate/s
        File caCertFile1   = new File("TIB-API-CA.crt"); 
        File caCertFile2   = new File("TibadoUSDCA.crt");
        byte[][] trustedCerts = new byte[2][];
        
        if(caCertFile1.canRead() && caCertFile2.canRead()){
            trustedCerts[0] = Files.readAllBytes(caCertFile1.toPath());
            trustedCerts[1] = Files.readAllBytes(caCertFile2.toPath());
        } else {
            System.out.println("Failed to read trusted certs.");
            return;
        }
  
        // TLS Remote Host
        // Replace with you own TLS servers address
        String host = "sitea.tibado.com";       
        Socket socket = new Socket(host, 443);
        
        // Generate Random Number
        SecureRandom secureRandom = new SecureRandom();

        // Setup TLS Protocol
        TlsClientProtocol tlsClientProtocol = new TlsClientProtocol(
                socket.getInputStream(), socket.getOutputStream(), secureRandom);

        // Setup AnyCard driver, Note: the anycard driver is for demo without a mxkey card only. 
        Smartcard smartcard = new AnyCard();
        smartcard.personalise(Files.readAllBytes(clientKeyFile.toPath()), Files.readAllBytes(clientCertFile.toPath()));

        SmartcardTlsClient client = new SmartcardTlsClient(host, smartcard, trustedCerts);

        tlsClientProtocol.connect(client);

        //////////////////////////////////////////////////
        OutputStream output = tlsClientProtocol.getOutputStream();
        String reqHeader = "GET /info HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
        output.write(reqHeader.getBytes("UTF-8"));

        InputStream input = tlsClientProtocol.getInputStream();
        System.out.println(convertStreamToString(input));

        tlsClientProtocol.close();
        socket.close();
        
    
}
