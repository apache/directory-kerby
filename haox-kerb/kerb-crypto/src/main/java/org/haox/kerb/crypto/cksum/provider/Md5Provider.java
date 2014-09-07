package org.haox.kerb.crypto.cksum.provider;

import org.haox.kerb.spec.KrbException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Md5Provider extends MessageDigestHashProvider {

    public Md5Provider() {
        super(16, 64, "MD5");
    }
}
