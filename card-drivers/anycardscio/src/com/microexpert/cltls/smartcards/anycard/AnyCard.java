/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.microexpert.cltls.smartcards.anycard;

import com.microexpert.cltls.core.Smartcard;
import com.microexpert.cltls.core.util.Util;
import java.io.IOException;
import java.math.BigInteger;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.asn1.pkcs.RSAPublicKey;
import org.spongycastle.crypto.AsymmetricBlockCipher;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.params.AsymmetricKeyParameter;
import org.spongycastle.crypto.tls.Certificate;

/**
 *
 * @author John
 */
public class AnyCard implements Smartcard {
    private AsymmetricBlockCipher   engine = new PKCS1Encoding(new RSABlinder());
    private AsymmetricKeyParameter  key;
    private Certificate             certificate;
    private int                     keySize;
        
    public void personalise(byte[] keyResource, byte[] clientCertificate) throws IOException{
        this.certificate                    = Util.loadCertificate(clientCertificate);
        ASN1Primitive clientPublicKeyASN    = this.certificate.getCertificateAt(0).getSubjectPublicKeyInfo().parsePublicKey();
        RSAPublicKey clientPublicKey        = RSAPublicKey.getInstance(clientPublicKeyASN);
        BigInteger mod                      = clientPublicKey.getModulus();
        this.keySize                        = mod.bitLength();
        this.key                            = Util.loadPrivateKeyResource(keyResource);
        this.engine.init(true, this.key);
    }
    
    @Override
    public byte[] encryptBlock(byte[] bytes, int i, int i1) throws IOException {
        try {
            return this.engine.processBlock(bytes, i, i1);
        } catch (InvalidCipherTextException ex) {
            throw new IOException("");
        }
    }
    
    @Override
    public Certificate getClientCertificate() {
        return this.certificate;
    }


    
}
