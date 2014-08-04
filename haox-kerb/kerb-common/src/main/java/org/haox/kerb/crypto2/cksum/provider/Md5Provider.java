package org.haox.kerb.crypto2.cksum.provider;

import org.haox.kerb.spec.KrbException;

import java.security.MessageDigest;

public class Md5Provider extends AbstractHashProvider {

    public Md5Provider() {
        super(16, 64);
    }

    @Override
    public byte[] hash(byte[] data, int start, int size) throws KrbException {
        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (Exception e) {
            throw new KrbException("Failed to init JCE provider", e);
        }
        try {
            md5.update(data);
            return md5.digest();
        } catch (Exception e) {
            throw new KrbException(e.getMessage());
        }
    }
}
