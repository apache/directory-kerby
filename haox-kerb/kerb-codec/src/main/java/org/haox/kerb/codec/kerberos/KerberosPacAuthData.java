package org.haox.kerb.codec.kerberos;

import java.security.Key;

import org.haox.kerb.codec.DecodingException;
import org.haox.kerb.codec.pac.Pac;

public class KerberosPacAuthData extends KerberosAuthData {

    private Pac pac;

    public KerberosPacAuthData(byte[] token, Key key) throws DecodingException {
        pac = new Pac(token, key);
    }

    public Pac getPac() {
        return pac;
    }

}
