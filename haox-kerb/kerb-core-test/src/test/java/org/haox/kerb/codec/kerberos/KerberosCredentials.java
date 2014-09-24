package org.haox.kerb.codec.kerberos;

import org.haox.kerb.keytab.Keytab;
import org.haox.kerb.keytab.KeytabEntry;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.common.PrincipalName;

import java.io.IOException;
import java.io.InputStream;

public class KerberosCredentials {

    private static Keytab keytab;

    private static void init() throws IOException {
        InputStream kis = KerberosCredentials.class.getResourceAsStream("/server.keytab");
        keytab = new Keytab();
        keytab.load(kis);
    }

    public static EncryptionKey getServerKey(EncryptionType etype) throws IOException {
        if (keytab == null) {
            init();
        }

        for (PrincipalName principal : keytab.getPrincipals()) {
            for (KeytabEntry entry : keytab.getKeytabEntries(principal)) {
                if (entry.getKey().getKeyType() == etype) {
                    return entry.getKey();
                }
            }
        }
        return null;
    }
}
