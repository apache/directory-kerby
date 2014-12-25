package org.haox.kerb.crypto.cksum.provider;

import org.haox.kerb.KrbException;

public class Md5Provider extends MessageDigestHashProvider {

    public Md5Provider() {
        super(16, 64, "MD5");
    }
}
