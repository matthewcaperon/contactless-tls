/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.microexpert.microkey.core;

import java.io.IOException;

import org.spongycastle.crypto.AsymmetricBlockCipher;
import org.spongycastle.crypto.CryptoException;
import org.spongycastle.crypto.params.AsymmetricKeyParameter;
import org.spongycastle.crypto.tls.Certificate;
import org.spongycastle.crypto.tls.SignatureAndHashAlgorithm;
import org.spongycastle.crypto.tls.TlsContext;
import org.spongycastle.crypto.tls.TlsSigner;
import org.spongycastle.crypto.tls.TlsSignerCredentials;
import org.spongycastle.crypto.tls.TlsUtils;

/**
 *
 * @author John
 */
public class SmartcardTlsSignerCredentials implements TlsSignerCredentials{

    protected TlsContext context;
    protected Certificate certificate;
    protected AsymmetricKeyParameter privateKey;
    protected SignatureAndHashAlgorithm signatureAndHashAlgorithm;
    protected TlsSigner signer;

    SmartcardTlsSignerCredentials(TlsContext context, Smartcard smartcard, Certificate certificate)
    {
        this(context, smartcard, certificate, null);
    }

    SmartcardTlsSignerCredentials(TlsContext context, Smartcard smartcard, Certificate certificate, SignatureAndHashAlgorithm signatureAndHashAlgorithm)
    {
        if (certificate == null)
        {
            throw new IllegalArgumentException("'certificate' cannot be null");
        }
        if (certificate.isEmpty())
        {
            throw new IllegalArgumentException("'certificate' cannot be empty");
        }

        
        if (TlsUtils.isTLSv12(context) && signatureAndHashAlgorithm == null)
        {
            throw new IllegalArgumentException("'signatureAndHashAlgorithm' cannot be null for (D)TLS 1.2+");
        }


        this.signer = new SmartcardTlsRSASigner(smartcard);
        this.signer.init(context);
        this.context = context;
        this.certificate = certificate;
        this.signatureAndHashAlgorithm = signatureAndHashAlgorithm;
    }

    public Certificate getCertificate()
    {
        return certificate;
    }

    public byte[] generateCertificateSignature(byte[] hash)
        throws IOException
    {
        try
        {
            if (TlsUtils.isTLSv12(context))
            {
                return signer.generateRawSignature(signatureAndHashAlgorithm, privateKey, hash);
            }
            else
            {
                return signer.generateRawSignature(privateKey, hash);
            }
        }
        catch (CryptoException e)
        {
            e.printStackTrace();
           // throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
        return null;
    }

    public SignatureAndHashAlgorithm getSignatureAndHashAlgorithm()
    {
        return signatureAndHashAlgorithm;
    }
    
}
