package org.haox.kerb.crypto.cksum.provider;

import org.haox.kerb.spec.KrbException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Md5Provider extends AbstractHashProvider {
    private MessageDigest md5;

    public Md5Provider() {
        super(16, 64);
    }

    @Override
    public void init() {
        try {
            md5 = MessageDigest.getInstance("MD5"); // HmacMD5 ?
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to init JCE provider", e);
        }
    }

    @Override
    public void hash(byte[] data, int start, int len) throws KrbException {
        md5.update(data, start, len);
    }

    @Override
    public byte[] output() {
        return md5.digest();
    }
}
