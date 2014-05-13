package org.haox.kerb.codec.kerberos;

import org.haox.kerb.codec.DecodingException;
import org.haox.kerb.codec.pac.Pac;

import java.security.Key;

public class KerberosPacAuthData extends KerberosAuthData {

    private Pac pac;

    public KerberosPacAuthData(byte[] token, Key key) throws DecodingException {
        pac = new Pac(token, key);
    }

    public Pac getPac() {
        return pac;
    }

}
