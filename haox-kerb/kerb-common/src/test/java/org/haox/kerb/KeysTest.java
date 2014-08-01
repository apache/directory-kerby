package org.haox.kerb;

import org.haox.kerb.crypto2.EncryptionHandler;
import org.haox.kerb.keytab.Keytab;
import org.haox.kerb.keytab.KeytabEntry;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.PrincipalName;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

/*
The principal was created with password '123456'

KVNO Timestamp         Principal
---- ----------------- --------------------------------------------------------
   1 07/30/14 18:45:53 test@SH.INTEL.COM (aes256-cts-hmac-sha1-96)
   1 07/30/14 18:45:53 test@SH.INTEL.COM (aes128-cts-hmac-sha1-96)
   1 07/30/14 18:45:53 test@SH.INTEL.COM (des3-cbc-sha1)
   1 07/30/14 18:45:53 test@SH.INTEL.COM (arcfour-hmac)
 */
public class KeysTest {
    private static String TEST_PASSWORD = "123456";

    private Keytab keytab;

    @Before
    public void setUp() throws IOException {
        InputStream kis = KeysTest.class.getResourceAsStream("/test.keytab");
        keytab = new Keytab();
        keytab.load(kis);
    }

    @Test
    public void testKeytab() {
        Assert.assertNotNull(keytab);
    }

    @Test
    public void testKeytabKeys() {
        List<PrincipalName> principals = keytab.getPrincipals();
        PrincipalName principal = principals.get(0);
        List<KeytabEntry> entries = keytab.getKeytabEntries(principal);
        for (KeytabEntry ke : entries) {
            Assert.assertTrue(ke.getKvno() == 1);
        }
    }

    @Test
    public void testString2Key() throws KrbException {
        List<PrincipalName> principals = keytab.getPrincipals();
        PrincipalName principal = principals.get(0);
        List<KeytabEntry> entries = keytab.getKeytabEntries(principal);
        EncryptionKey genKey;
        for (KeytabEntry ke : entries) {
            genKey = EncryptionHandler.string2Key(principal.getName(),
                    TEST_PASSWORD, ke.getKey().getKeyType());
            Assert.assertTrue(ke.getKey().equals(genKey));
        }
    }

    public static void main(String[] args) throws IOException {
        InputStream kis = KeysTest.class.getResourceAsStream("test.keytab");
        Keytab keytab = new Keytab();
        keytab.load(kis);
        System.out.println("Principals:" + keytab.getPrincipals().size());
    }
}
