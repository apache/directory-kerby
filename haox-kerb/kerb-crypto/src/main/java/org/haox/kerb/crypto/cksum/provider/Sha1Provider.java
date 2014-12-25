package org.haox.kerb.crypto.cksum.provider;

import org.haox.kerb.KrbException;

public class Sha1Provider extends MessageDigestHashProvider {

    public Sha1Provider() {
        super(20, 64, "SHA1");
    }
}
