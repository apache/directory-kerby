package org.haox.kerb.crypto.cksum.provider;

public class Md4Provider extends MessageDigestHashProvider {

    public Md4Provider() {
        super(16, 64, "MD4");
    }
}
