/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.microexpert.cltls.core.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.cert.CertificateEncodingException;
import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.asn1.pkcs.RSAPrivateKey;
import org.spongycastle.asn1.util.ASN1Dump;
import org.spongycastle.crypto.params.AsymmetricKeyParameter;
import org.spongycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.spongycastle.crypto.tls.TlsUtils;
import org.spongycastle.crypto.util.PrivateKeyFactory;
import org.spongycastle.util.encoders.Base64;
import org.spongycastle.util.io.pem.PemObject;
import org.spongycastle.util.io.pem.PemReader;

/**
 *
 * @author John
 */
public class Util {
    
        // Unpacking the Private Key components
    public static AsymmetricKeyParameter loadPrivateKeyResource(byte[] resource)
        throws IOException
    {
        PemObject pem = loadPemResource(resource);
        if (pem.getType().endsWith("RSA PRIVATE KEY"))
        {
            RSAPrivateKey rsa = RSAPrivateKey.getInstance(pem.getContent());
            return new RSAPrivateCrtKeyParameters(rsa.getModulus(), rsa.getPublicExponent(),
                rsa.getPrivateExponent(), rsa.getPrime1(), rsa.getPrime2(), rsa.getExponent1(),
                rsa.getExponent2(), rsa.getCoefficient());
        }
        if (pem.getType().endsWith("PRIVATE KEY"))
        {
            return PrivateKeyFactory.createKey(pem.getContent());
        }
        throw new IllegalArgumentException("'resource' doesn't specify a valid private key");
    }

    public static PemObject loadPemResource(byte[] resource)
            throws IOException {
        InputStream s = new ByteArrayInputStream(resource);
        PemReader p = new PemReader(new InputStreamReader(s));
        PemObject o = p.readPemObject();
        p.close();
        return o;
    }
    
    public static org.spongycastle.crypto.tls.Certificate loadCertificateChain(byte[][] resources)
        throws IOException
    {
        org.spongycastle.asn1.x509.Certificate[] chain = new org.spongycastle.asn1.x509.Certificate[resources.length];
                
        for (int i = 0; i < resources.length; ++i)
        {
            chain[i] = loadPEMorDERCertificateResource(resources[i]);
        }
        return new org.spongycastle.crypto.tls.Certificate(chain);
    }
    
    public static org.spongycastle.crypto.tls.Certificate loadCertificate(byte[] resource)
        throws IOException
    {
 
        org.spongycastle.asn1.x509.Certificate[] cert = new org.spongycastle.asn1.x509.Certificate[1];
        cert[0] = loadPEMorDERCertificateResource(resource);
        
        return new org.spongycastle.crypto.tls.Certificate(cert);
    }

    public static org.spongycastle.asn1.x509.Certificate loadPEMorDERCertificateResource(byte[] resource)
            throws IOException {
        PemObject pem;
        try {
            pem = loadPemResource(resource);
            pem.getType().endsWith("CERTIFICATE");
            return org.spongycastle.asn1.x509.Certificate.getInstance(pem.getContent());
        } catch (NullPointerException e){
            
            // Try as DER
            try {
                ASN1Primitive asn1Cert = TlsUtils.readDERObject(resource);
                return org.spongycastle.asn1.x509.Certificate.getInstance(asn1Cert);
            } catch (Exception ee){
                throw new IllegalArgumentException("'resource' doesn't specify a valid certificate");    
            }
            
        }
        
    }

    
    public static byte[] convertToPem(byte[] derCert) throws CertificateEncodingException {
        Base64 encoder = new Base64();
        String cert_begin = "-----BEGIN CERTIFICATE-----\n";
        String end_cert = "-----END CERTIFICATE-----";

        String pemCertPre = new String(encoder.encode(derCert));
        String pemCert = cert_begin + pemCertPre + end_cert;
        System.out.println(pemCert);
        return pemCert.getBytes();
    }
    
    
}
