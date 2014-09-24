package org.haox.kerb.crypto.cksum.provider;

import org.haox.kerb.spec.KrbException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MessageDigestHashProvider extends AbstractHashProvider {
    private String algorithm;
    protected MessageDigest messageDigest;

    public MessageDigestHashProvider(int hashSize, int blockSize, String algorithm) {
        super(hashSize, blockSize);
        this.algorithm = algorithm;

        init();
    }

    @Override
    protected void init() {
        try {
            messageDigest = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to init JCE provider", e);
        }
    }

    @Override
    public void hash(byte[] data, int start, int len) throws KrbException {
        messageDigest.update(data, start, len);
    }

    @Override
    public byte[] output() {
        return messageDigest.digest();
    }
}
