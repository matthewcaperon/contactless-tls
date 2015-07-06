/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.microexpert.cltls.samples.desktopsample;

import com.microexpert.cltls.core.Smartcard;
import com.microexpert.cltls.core.SmartcardTlsClient;
import com.microexpert.cltls.smartcards.softcard.SoftCard;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.util.List;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import org.spongycastle.crypto.tls.TlsClientProtocol;

/**
 *
 * @author John
 */
public class DesktopClient {

    public static void main(String[] args) throws IOException, CertificateEncodingException, CardException {
        
        ///////////////////// SETUP //////////////////////////////
        
        // Trusted Certificate Authorities 
        // Replace with you own CA certificate/s
        File caCertFile1   = new File("ca1.crt"); 
        File caCertFile2   = new File("ca2.crt");
        byte[][] trustedCerts = new byte[2][];
        
        if(caCertFile1.canRead() && caCertFile2.canRead()){
            trustedCerts[0] = Files.readAllBytes(caCertFile1.toPath());
            trustedCerts[1] = Files.readAllBytes(caCertFile2.toPath());
        } else {
            System.out.println("Failed to read trusted certs.");
            return;
        }
  
        // The AnyCard driver requires client certificate and key
        File clientCertFile = new File("client.crt"); 
        File clientKeyFile = new File("client.key");
        
        // TLS Remote Host
        // Replace with you own TLS servers address
        String host = "sitea.tibado.com";       
        Socket socket = new Socket(host, 443);
        
        // Get List of connected PC/SC smartcard readers
        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();
        CardTerminal selectedTerminal = terminals.get(0); // Getting first available reader
        
        System.out.println("Waiting for card....");
        
        selectedTerminal.waitForCardPresent(10000);
        if(selectedTerminal.isCardPresent()){
        
            // Setup SoftCard driver, Note: the softcard driver is for demo without a mxkey card only. 
            Smartcard smartcard = new SoftCard( 
                    Files.readAllBytes(clientKeyFile.toPath()), 
                    Files.readAllBytes(clientCertFile.toPath()));

            // For MicroKey Card
            //Microkey smartcard = new Microkey(terminals.get(0));

            // Generate Random Number
            SecureRandom secureRandom = new SecureRandom();

            // Setup TLS Protocol
            TlsClientProtocol tlsClientProtocol = new TlsClientProtocol(
                    socket.getInputStream(), socket.getOutputStream(), secureRandom);


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
        } else {
            System.out.println("Card not Found.");
        }
        
    }
    
    static String convertStreamToString(java.io.InputStream is) {
        java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";
    }
}
