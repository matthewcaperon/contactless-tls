/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.microexpert.microkey.core;

import org.spongycastle.crypto.AsymmetricBlockCipher;
import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.CryptoException;
import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.Signer;
import org.spongycastle.crypto.digests.NullDigest;
import org.spongycastle.crypto.encodings.PKCS1Encoding;
import org.spongycastle.crypto.params.AsymmetricKeyParameter;
import org.spongycastle.crypto.params.ParametersWithRandom;
import org.spongycastle.crypto.params.RSAKeyParameters;
import org.spongycastle.crypto.signers.GenericSigner;
import org.spongycastle.crypto.tls.AbstractTlsSigner;
import org.spongycastle.crypto.tls.SignatureAlgorithm;
import org.spongycastle.crypto.tls.SignatureAndHashAlgorithm;
import org.spongycastle.crypto.tls.TlsSigner;
import org.spongycastle.crypto.tls.TlsUtils;

/**
 *
 * @author John
 */
public class SmartcardTlsRSASigner extends AbstractTlsSigner implements TlsSigner {

    Smartcard smartcard;

    SmartcardTlsRSASigner(Smartcard smartcard){
        this.smartcard = smartcard;
    }

    @Override
    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm,
        AsymmetricKeyParameter privateKey, byte[] hash)
        throws CryptoException
    {
        Signer signer = makeSigner(algorithm, true, true,
            new ParametersWithRandom(privateKey, this.context.getSecureRandom()));
        signer.update(hash, 0, hash.length);
        return signer.generateSignature();
    }

    @Override
    public boolean verifyRawSignature(SignatureAndHashAlgorithm algorithm, byte[] sigBytes,
        AsymmetricKeyParameter publicKey, byte[] hash)
        throws CryptoException
    {
        Signer signer = makeSigner(algorithm, true, false, publicKey);
        signer.update(hash, 0, hash.length);
        return signer.verifySignature(sigBytes);
    }

    @Override
    public Signer createSigner(SignatureAndHashAlgorithm algorithm, AsymmetricKeyParameter privateKey)
    {
        return makeSigner(algorithm, false, true, new ParametersWithRandom(privateKey, this.context.getSecureRandom()));
    }

    @Override
    public Signer createVerifyer(SignatureAndHashAlgorithm algorithm, AsymmetricKeyParameter publicKey)
    {
        return makeSigner(algorithm, false, false, publicKey);
    }

    @Override
    public boolean isValidPublicKey(AsymmetricKeyParameter publicKey)
    {
        return publicKey instanceof RSAKeyParameters && !publicKey.isPrivate();
    }

    protected Signer makeSigner(SignatureAndHashAlgorithm algorithm, boolean raw, boolean forSigning,
        CipherParameters cp)
    {
        if ((algorithm != null) != TlsUtils.isTLSv12(context))
        {
            throw new IllegalStateException();
        }

        if (algorithm != null && algorithm.getSignature() != SignatureAlgorithm.rsa)
        {
            throw new IllegalStateException();
        }

        Digest d;
        if (raw)
        {
            d = new NullDigest();
        }
        /*else if (algorithm == null)
        {
            d = new CombinedHash();
        }*/
        else
        {
            d = TlsUtils.createHash(algorithm.getHash());
        }

        Signer s;
        if (algorithm != null)
        {
            /*
             * RFC 5246 4.7. In RSA signing, the opaque vector contains the signature generated
             * using the RSASSA-PKCS1-v1_5 signature scheme defined in [PKCS1].
             */
            s = new SmartcardRSADigestSigner(smartcard, d, TlsUtils.getOIDForHashAlgorithm(algorithm.getHash()));
        }
        else
        {
            /*
             * RFC 5246 4.7. Note that earlier versions of TLS used a different RSA signature scheme
             * that did not include a DigestInfo encoding.
             */

            s = new SmartcardGenericSigner(createRSAImpl(), d);
        }
        s.init(forSigning, cp);
        return s;
    }

    protected Smartcard createRSAImpl()
    {
        /*
         * RFC 5264 7.4.7.1. Implementation note: It is now known that remote timing-based attacks
         * on TLS are possible, at least when the client and server are on the same LAN.
         * Accordingly, implementations that use static RSA keys MUST use RSA blinding or some other
         * anti-timing technique, as described in [TIMING].
         */
        return smartcard;
    }
    
}
