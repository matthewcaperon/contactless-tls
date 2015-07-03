/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.microexpert.cltls.core;

import java.io.IOException;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.tls.Certificate;

/**
 *
 * @author John
 */
public interface Smartcard { //RSA MicroKey Smartcard
    
    //public int getKeySize();
    // TODO: remove offset and length, are they used?
    public byte[] encryptBlock(byte[] bytes, int i, int i1) throws IOException;
    public Certificate getClientCertificate() throws IOException;
    
}
