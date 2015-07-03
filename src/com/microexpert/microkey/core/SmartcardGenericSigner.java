package com.microexpert.microkey.core;

import java.util.logging.Level;
import java.util.logging.Logger;
import org.spongycastle.crypto.AsymmetricBlockCipher;
import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.CryptoException;
import org.spongycastle.crypto.DataLengthException;
import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.Signer;
import org.spongycastle.crypto.params.AsymmetricKeyParameter;
import org.spongycastle.crypto.params.ParametersWithRandom;
import org.spongycastle.util.Arrays;

public class SmartcardGenericSigner
    implements Signer
{
    private final Smartcard smartcard;
    private final Digest digest;
    private boolean forSigning;

    public SmartcardGenericSigner(
        Smartcard             smartcard,
        Digest                digest)
    {
        this.smartcard = smartcard;
        this.digest = digest;
    }

    /**
     * initialise the signer for signing or verification.
     *
     * @param forSigning
     *            true if for signing, false otherwise
     * @param parameters
     *            necessary parameters.
     */
    public void init(
        boolean          forSigning,
        CipherParameters parameters)
    {
        this.forSigning = forSigning;
        reset();
    }

    /**
     * update the internal digest with the byte b
     */
    public void update(
        byte input)
    {
        digest.update(input);
    }

    /**
     * update the internal digest with the byte array in
     */
    public void update(
        byte[]  input,
        int     inOff,
        int     length)
    {
        digest.update(input, inOff, length);
    }

    /**
     * Generate a signature for the message we've been loaded with using the key
     * we were initialised with.
     */
    public byte[] generateSignature()
        throws CryptoException, DataLengthException
    {
        if (!forSigning)
        {
            throw new IllegalStateException("GenericSigner not initialised for signature generation.");
        }

        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        
        try {
            return smartcard.encryptBlock(hash, 0, hash.length);
        } catch (Exception e) {
            throw new CryptoException("unable to encode signature: " + e.getMessage(), e);
        }
    }

    /**
     * return true if the internal state represents the signature described in
     * the passed in array.
     */
    public boolean verifySignature(
        byte[] signature)
    {
        if (forSigning)
        {
            throw new IllegalStateException("GenericSigner not initialised for verification");
        }

        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        try
        {
            byte[] sig = smartcard.encryptBlock(signature, 0, signature.length);

            // Extend with leading zeroes to match the digest size, if necessary.
            if (sig.length < hash.length)
            {
                byte[] tmp = new byte[hash.length];
                System.arraycopy(sig, 0, tmp, tmp.length - sig.length, sig.length);
                sig = tmp;
            }

            return Arrays.constantTimeAreEqual(sig, hash);
        }
        catch (Exception e)
        {
            return false;
        }
    }

    public void reset()
    {
        digest.reset();
    }
}
