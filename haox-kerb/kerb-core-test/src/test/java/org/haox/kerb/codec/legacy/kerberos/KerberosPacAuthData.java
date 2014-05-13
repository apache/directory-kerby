package org.haox.kerb.codec.legacy.kerberos;

import java.security.Key;

import org.haox.kerb.codec.legacy.DecodingException;
import org.haox.kerb.codec.legacy.pac.Pac;

public class KerberosPacAuthData extends KerberosAuthData {

    private Pac pac;

    public KerberosPacAuthData(byte[] token, Key key) throws DecodingException {
        pac = new Pac(token, key);
    }

    public Pac getPac() {
        return pac;
    }

}
