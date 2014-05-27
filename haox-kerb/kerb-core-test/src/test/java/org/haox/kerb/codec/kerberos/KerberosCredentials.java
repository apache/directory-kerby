package org.haox.kerb.codec.kerberos;

import org.haox.kerb.keytab.Keytab;
import org.haox.kerb.keytab.KeytabEntry;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.common.PrincipalName;

import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosPrincipal;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;

public class KerberosCredentials {

    private static Keytab keytab;

    private static void init() throws IOException {
        InputStream kis = KerberosCredentials.class.getResourceAsStream("/server.keytab");
        keytab = new Keytab();
        keytab.load(kis);
    }

    public static Key getServerKey(EncryptionType etype) throws IOException {
        if (keytab == null) {
            init();
        }

        for (PrincipalName principal : keytab.getPrincipals()) {
            for (KeytabEntry entry : keytab.getKeytabEntries(principal)) {
                if (entry.getKey().getKeyType() == etype) {
                    return convert(entry);
                }
            }
        }
        return null;
    }

    private static Key convert(KeytabEntry entry) {
        KerberosPrincipal krbPrinc = new KerberosPrincipal(
                entry.getPrincipal().getName(),
                entry.getPrincipal().getNameType().getValue());
        Key key = new KerberosKey(krbPrinc,
                entry.getKey().getKeyData(),
                entry.getKey().getKeyType().getValue(),
                entry.getKvno());

        return key;
    }
}
