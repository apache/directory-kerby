package org.apache.kerberos.kerb.crypto.cksum.provider;

public class Md5Provider extends MessageDigestHashProvider {

    public Md5Provider() {
        super(16, 64, "MD5");
    }
}
