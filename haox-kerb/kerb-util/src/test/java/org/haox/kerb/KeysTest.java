package org.haox.kerb;

import org.haox.kerb.crypto.EncryptionHandler;
import org.haox.kerb.keytab.Keytab;
import org.haox.kerb.keytab.KeytabEntry;
import org.haox.kerb.KrbException;
import org.haox.kerb.spec.common.EncryptionKey;
import org.haox.kerb.spec.common.EncryptionType;
import org.haox.kerb.spec.common.PrincipalName;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

/*
The principal was created with password '123456'
KVNO Principal
---- --------------------------------------------------------------------------
   1 test@SH.INTEL.COM (des-cbc-crc)
   1 test@SH.INTEL.COM (des3-cbc-sha1)
   1 test@SH.INTEL.COM (des-hmac-sha1)
   1 test@SH.INTEL.COM (aes256-cts-hmac-sha1-96)
   1 test@SH.INTEL.COM (aes128-cts-hmac-sha1-96)
   1 test@SH.INTEL.COM (arcfour-hmac)
   1 test@SH.INTEL.COM (camellia256-cts-cmac)
   1 test@SH.INTEL.COM (camellia128-cts-cmac)
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
    public void testString2Key() throws KrbException {
        List<PrincipalName> principals = keytab.getPrincipals();
        PrincipalName principal = principals.get(0);
        List<KeytabEntry> entries = keytab.getKeytabEntries(principal);
        EncryptionKey genKey;
        EncryptionType keyType;
        for (KeytabEntry ke : entries) {
            keyType = ke.getKey().getKeyType();
            if (EncryptionHandler.isImplemented(keyType)) {
                genKey = EncryptionHandler.string2Key(principal.getName(),
                        TEST_PASSWORD, keyType);
                if(! ke.getKey().equals(genKey)) {
                    Assert.fail("str2key failed for key type: " + keyType.getName());
                    //System.err.println("str2key failed for key type: " + keyType.getName());
                }
            }
        }
    }
}
