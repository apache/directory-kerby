package org.haox.kerb.codec.kerberos;

import java.security.Key;
import java.util.ArrayList;
import java.util.List;

import org.haox.kerb.codec.DecodingException;

public abstract class KerberosAuthData {

    public static List<KerberosAuthData> parse(int authType, byte[] token, Key key)
            throws DecodingException {

        List<KerberosAuthData> authorizations = new ArrayList<KerberosAuthData>();

        switch (authType) {
        case KerberosConstants.AUTH_DATA_RELEVANT:
            authorizations = new KerberosRelevantAuthData(token, key).getAuthorizations();
            break;
        case KerberosConstants.AUTH_DATA_PAC:
            authorizations.add(new KerberosPacAuthData(token, key));
            break;
        default:
        }

        return authorizations;
    }

}
