package org.haox.kerb.decoding.kerberos;

import java.security.Key;

import org.haox.kerb.decoding.DecodingException;
import org.haox.kerb.decoding.pac.Pac;

public class KerberosPacAuthData extends KerberosAuthData {

    private Pac pac;

    public KerberosPacAuthData(byte[] token, Key key) throws DecodingException {
        pac = new Pac(token, key);
    }

    public Pac getPac() {
        return pac;
    }

}
