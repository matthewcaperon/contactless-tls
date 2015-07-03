/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.microexpert.microkey.core;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Hashtable;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.asn1.pkcs.RSAPublicKey;
import org.spongycastle.asn1.x509.Certificate;

import org.spongycastle.crypto.tls.CipherSuite;
import org.spongycastle.crypto.tls.DefaultTlsClient;
import org.spongycastle.crypto.tls.ExtensionType;
import org.spongycastle.crypto.tls.ProtocolVersion;
import org.spongycastle.crypto.tls.TlsAuthentication;


/**
 *
 * @author John
 */
public class SmartcardTlsClient extends DefaultTlsClient {

    private String  hostname;
    Smartcard       smartcard;
    byte[][]        caCertChain; 

    public SmartcardTlsClient(String hostname, Smartcard smartcard,
                              byte[][] caCertChain) throws IOException {
        super();
        this.hostname = hostname;
        this.smartcard = smartcard;
        this.caCertChain = caCertChain;
    }


    @Override
    public TlsAuthentication getAuthentication() throws IOException {
        return new SmartcardTlsAuthentication(context, smartcard, caCertChain);
    }

    @Override
    public Hashtable<Integer, byte[]> getClientExtensions() throws IOException {
        @SuppressWarnings("unchecked")
        Hashtable<Integer, byte[]> clientExtensions = super.getClientExtensions();
        if (clientExtensions == null) {
            clientExtensions = new Hashtable<Integer, byte[]>();
        }

        final ByteArrayOutputStream extBaos = new ByteArrayOutputStream();
        final DataOutputStream extOS = new DataOutputStream(extBaos);

        if (this.hostname != null) {
            System.out.println("Hostname:" + this.hostname);
            final byte[] hostnameBytes = this.hostname.getBytes();
            final int snl = hostnameBytes.length;

            // OpenSSL breaks if an extension with length "0" sent, they expect
            // at least
            // an entry with length "0"
            extOS.writeShort(snl == 0 ? 0 : snl + 3); // entry size
            if (snl > 0) {
                extOS.writeByte(0); // name type = hostname
                extOS.writeShort(snl); // name size
                if (snl > 0) {
                    extOS.write(hostnameBytes);
                }
            }

            extOS.close();
            clientExtensions.put(ExtensionType.server_name, extBaos.toByteArray());
        }

        return clientExtensions;
    }

    @Override
    public int[] getCipherSuites() // Supportted Cipher Specs
    {
        return new int[]
        {
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            //CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
            //CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
            //CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
        };
    }
    
    @Override
    public ProtocolVersion getClientVersion()
    {
        /* TLS 1.2 produces a digest too long for a single block encrypt operation on small keys */

        Certificate clientCertificate;
        try {
            clientCertificate = this.smartcard.getClientCertificate().getCertificateAt(0);
        } catch (IOException ex) {
            return ProtocolVersion.TLSv11;
        }
        // If RSA (Only RSA keys are supportted)
        if(clientCertificate.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm().getId().contentEquals("1.2.840.113549.1.1.1")){
            ASN1Primitive clientPublicKey;
            try {
                clientPublicKey = clientCertificate.getSubjectPublicKeyInfo().parsePublicKey();
            } catch (IOException ex) {
                return ProtocolVersion.TLSv11;
            }
            RSAPublicKey clientRSAPublicKey = RSAPublicKey.getInstance(clientPublicKey);
            if (clientRSAPublicKey.getModulus().bitCount() >= 1024) {
                return ProtocolVersion.TLSv12;
            } else {
                return ProtocolVersion.TLSv11;
            }
        } else {
            //TODO handle failure
            return ProtocolVersion.TLSv11;
        }

    }

}
