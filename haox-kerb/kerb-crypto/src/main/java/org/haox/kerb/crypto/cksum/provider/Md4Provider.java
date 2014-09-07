package org.haox.kerb.crypto.cksum.provider;

import org.haox.kerb.crypto.Md4;

public class Md4Provider extends MessageDigestHashProvider {

    public Md4Provider() {
        super(16, 64, "MD4");
    }

    @Override
    protected void init() {
        messageDigest = new Md4();
    }
}
