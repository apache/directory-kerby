package org.haox.kerb.crypto.cksum.provider;

import org.haox.kerb.spec.KrbException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Sha1Provider extends MessageDigestHashProvider {

    public Sha1Provider() {
        super(20, 64, "SHA1");
    }
}
