package org.haox.kerb;

import org.haox.kerb.ccache.CredentialCache;
import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.crypto.EncryptionHandler;
import org.haox.kerb.keytab.Keytab;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.*;
import org.haox.kerb.spec.type.ticket.EncTicketPart;
import org.haox.kerb.spec.type.ticket.Ticket;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;

/*
The principal keys for krbtgt/SH.INTEL.COM@SH.INTEL.COM

KVNO Principal
---- --------------------------------------------------------------------------
   2 krbtgt/SH.INTEL.COM@SH.INTEL.COM (des-cbc-crc)
   2 krbtgt/SH.INTEL.COM@SH.INTEL.COM (des3-cbc-raw)
   2 krbtgt/SH.INTEL.COM@SH.INTEL.COM (des-hmac-sha1)
   2 krbtgt/SH.INTEL.COM@SH.INTEL.COM (aes256-cts-hmac-sha1-96)
   2 krbtgt/SH.INTEL.COM@SH.INTEL.COM (aes128-cts-hmac-sha1-96)
   2 krbtgt/SH.INTEL.COM@SH.INTEL.COM (arcfour-hmac)
   2 krbtgt/SH.INTEL.COM@SH.INTEL.COM (camellia256-cts-cmac)
   2 krbtgt/SH.INTEL.COM@SH.INTEL.COM (camellia128-cts-cmac)
 */
public class EncryptionTest {

    private Keytab keytab;
    private CredentialCache cc;

    @Before
    public void setUp() throws IOException {
        InputStream kis = EncryptionTest.class.getResourceAsStream("/test.keytab");
        keytab = new Keytab();
        keytab.load(kis);
    }

    @Test
    public void testEncryption() throws KrbException, IOException {
        String[] ccFiles = new String[]{
                "aes128-cts-hmac-sha1-96.cc",
                "aes256-cts-hmac-sha1-96.cc",
                "arcfour-hmac.cc",
                "camellia128-cts-cmac.cc",
                "camellia256-cts-cmac.cc",
                "des3-cbc-sha1.cc",
                "des-cbc-crc.cc"
        };

        for (String ccFile : ccFiles) {
            testEncWith(ccFile);
            break;
        }
    }

    private void testEncWith(String ccFile) throws IOException, KrbException {
        InputStream cis = CcacheTest.class.getResourceAsStream("/" + ccFile);
        cc = new CredentialCache();
        cc.load(cis);

        Ticket ticket = getTicket();
        EncryptionType keyType = ticket.getEncryptedEncPart().getEType();
        EncryptionKey key = getServerKey(keyType);
        if (! EncryptionHandler.isSupported(keyType)) {
            System.err.println("Key type not supported yet: " + keyType.getName());
            return;
        }

        byte[] decrypted = EncryptionHandler.decrypt(
                ticket.getEncryptedEncPart(), key, KeyUsage.KDC_REP_TICKET);
        Assert.assertNotNull(decrypted);

        EncTicketPart encPart = KrbCodec.decode(decrypted, EncTicketPart.class);
        Assert.assertNotNull(encPart);
        ticket.setEncPart(encPart);

        EncryptedData encrypted = EncryptionHandler.encrypt(
                decrypted, key, KeyUsage.KDC_REP_TICKET);

        byte[] decrypted2 = EncryptionHandler.decrypt(
                encrypted, key, KeyUsage.KDC_REP_TICKET);
        if (! Arrays.equals(decrypted, decrypted2)) {
            System.err.println("Encryption checking failed after decryption for key type: "
                    + keyType.getName());
        }
    }

    private EncryptionKey getServerKey(EncryptionType keyType) {
        return keytab.getKey(getServer(), keyType);
    }

    private PrincipalName getServer() {
        // only one, krbtgt/SH.INTEL.COM@SH.INTEL.COM
        List<PrincipalName> principals = keytab.getPrincipals();
        PrincipalName server = principals.get(0);

        return server;
    }

    private Ticket getTicket() {
        return cc.getCredentials().get(0).getTicket();
    }
}
