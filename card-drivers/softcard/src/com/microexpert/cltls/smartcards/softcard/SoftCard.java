/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.microexpert.cltls.smartcards.softcard;

import com.microexpert.cltls.core.Smartcard;
import com.microexpert.cltls.core.util.Util;
import java.io.IOException;


import org.spongycastle.crypto.AsymmetricBlockCipher;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.params.AsymmetricKeyParameter;
import org.spongycastle.crypto.tls.Certificate;

/**
 *
 * @author John
 */
public class SoftCard implements Smartcard {
    private AsymmetricBlockCipher   engine = new PKCS1Encoding(new RSABlinder());
    private AsymmetricKeyParameter  key;
    private Certificate             certificate;
    
    public SoftCard(byte[] keyResource, byte[] clientCertificate) throws IOException{
        this.personalise(keyResource, clientCertificate);
    }
    
    private void personalise(byte[] keyResource, byte[] clientCertificate) throws IOException{
        this.certificate                    = Util.loadCertificate(clientCertificate);
        //ASN1Primitive clientPublicKeyASN    = this.certificate.getCertificateAt(0).getSubjectPublicKeyInfo().parsePublicKey();
        //RSAPublicKey clientPublicKey        = RSAPublicKey.getInstance(clientPublicKeyASN);
        //BigInteger mod                      = clientPublicKey.getModulus();
        //this.keySize                        = mod.bitLength();
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
