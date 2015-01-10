package org.apache.kerberos.kerb.crypto.cksum.provider;

public class Sha1Provider extends MessageDigestHashProvider {

    public Sha1Provider() {
        super(20, 64, "SHA1");
    }
}
