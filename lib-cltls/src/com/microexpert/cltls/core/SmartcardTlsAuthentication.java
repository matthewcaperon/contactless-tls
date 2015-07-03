/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.microexpert.cltls.core;

import com.microexpert.cltls.core.util.Util;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Vector;
import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.asn1.pkcs.RSAPublicKey;
import org.spongycastle.crypto.Signer;
import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.params.RSAKeyParameters;
import org.spongycastle.crypto.signers.RSADigestSigner;
import org.spongycastle.crypto.tls.Certificate;
import org.spongycastle.crypto.tls.CertificateRequest;
import org.spongycastle.crypto.tls.ClientCertificateType;
import org.spongycastle.crypto.tls.SignatureAlgorithm;
import org.spongycastle.crypto.tls.SignatureAndHashAlgorithm;
import org.spongycastle.crypto.tls.TlsAuthentication;
import org.spongycastle.crypto.tls.TlsClientContext;
import org.spongycastle.crypto.tls.TlsContext;
import org.spongycastle.crypto.tls.TlsCredentials;
import org.spongycastle.crypto.tls.TlsSignerCredentials;
import org.spongycastle.util.Arrays;


/**
 *
 * @author John
 */
public class SmartcardTlsAuthentication implements TlsAuthentication
{
    TlsClientContext    context;
    Smartcard           smartcard;
    Certificate         clientCertificate;
    Certificate         caCertificates;

    SmartcardTlsAuthentication(TlsClientContext context, Smartcard smartcard,
                               byte[][] caCertificateChain) throws IOException {
        this.context            = context;
        this.smartcard          = smartcard;   
        this.clientCertificate  = smartcard.getClientCertificate();
        this.caCertificates     = Util.loadCertificateChain(caCertificateChain);
    }
    
    @Override
    public void notifyServerCertificate(Certificate serverCertificates) throws IOException {
        System.out.println("Validating Server Certificate");
        boolean isValid = false;
        
        org.spongycastle.asn1.x509.Certificate serverCertificate = serverCertificates.getCertificateAt(0);
        System.out.println("Server Certificate Subject: " + serverCertificate.getSubject().toString());
        System.out.println("Server Certificate Issuer Subject: " + serverCertificate.getIssuer().toString());
        
        int numOfCaCerts = caCertificates.getLength();
        
        for(int i = 0; i < numOfCaCerts; i++){
            org.spongycastle.asn1.x509.Certificate caCertificate = caCertificates.getCertificateAt(i);
            System.out.println("CA Certificate Subject: " + caCertificate.getSubject().toString());
            
            /*
                OID value: 1.2.840.113549.1.1.1
                OID description:
                Identifier for RSA encryption for use with Public Key Cryptosystem One defined by RSA Inc. 
            */
            if(caCertificate.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm().getId().contentEquals("1.2.840.113549.1.1.1")){
                ASN1Primitive caPublicKey = caCertificate.getSubjectPublicKeyInfo().parsePublicKey();
                RSAPublicKey caRSAPublicKey = RSAPublicKey.getInstance(caPublicKey);
                RSAKeyParameters cp = new RSAKeyParameters(false, caRSAPublicKey.getModulus(), caRSAPublicKey.getPublicExponent());

                
                String digestAlgo = serverCertificate.getSignatureAlgorithm().getAlgorithm().getId();
                Signer signer;
                
                /*
                    OID value: 1.2.840.113549.1.1.11
                    OID description: SHA256 with RSA Encryption 
                */
                if(digestAlgo.contentEquals("1.2.840.113549.1.1.11")){
                    SHA256Digest digest = new SHA256Digest();
                    signer = new RSADigestSigner(digest);

                /*
                    OID value: 1.2.840.113549.1.1.5
                    OID description: Identifier for SHA-1checksum with RSA encryption. 
                */
                } else if(digestAlgo.contentEquals("1.2.840.113549.1.1.5")){
                    SHA1Digest digest = new SHA1Digest();
                    signer = new RSADigestSigner(digest);
                } else {
                    System.out.println("Digest Algorithm not supported.");
                    throw new IOException("Digest Algorithm not supported.");
                }
                

                byte[] toSign = serverCertificate.getTBSCertificate().getEncoded();
                signer.init(false, cp);
                signer.update(toSign, 0, toSign.length);

                if (signer.verifySignature(serverCertificate.getSignature().getBytes()) == true) {
                    isValid = true;
                    break;
                }
                   
            } else {
                System.out.println("Algorithm not supported.");
                throw new IOException("Algorithm not supported.");
            }
        }
        
        if (isValid) {
            System.out.println("Server Certicate is Valid.");
        } else {
            System.out.println("Warning Server Certicate is not trusted.");
            throw new IOException("Server Certicate is not trusted.");
        }
    }

    @Override
    public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) throws IOException {

        System.out.println("getting Client Credentials");

        short[] certificateTypes = certificateRequest.getCertificateTypes();
        if (certificateTypes == null || !Arrays.contains(certificateTypes, ClientCertificateType.rsa_sign)) {
            return null;
        }

        System.out.println("Loading signer Credentials");

        return loadSignerCredentials(this.context, certificateRequest.getSupportedSignatureAlgorithms());
    }
    
    //SmartcardTlsSignerCredentials
    public TlsSignerCredentials loadSignerCredentials(TlsContext context, Vector supportedSignatureAlgorithms)
            throws IOException {
        /*
         * TODO Note that this code fails to provide default value for the client supported
         * algorithms if it wasn't sent.
         */

        SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;
        if (supportedSignatureAlgorithms != null) {
            for (int i = 0; i < supportedSignatureAlgorithms.size(); ++i) {
                SignatureAndHashAlgorithm alg = (SignatureAndHashAlgorithm) supportedSignatureAlgorithms.elementAt(i);
                if (alg.getSignature() == SignatureAlgorithm.rsa) {
                    signatureAndHashAlgorithm = alg;
                    break;
                }
            }

            if (signatureAndHashAlgorithm == null) {
                return null;
            }
        }

        return new SmartcardTlsSignerCredentials(context, smartcard, clientCertificate, signatureAndHashAlgorithm);
        
    }
      
}
