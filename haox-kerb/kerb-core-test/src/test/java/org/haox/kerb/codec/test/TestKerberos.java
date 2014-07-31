package org.haox.kerb.codec.test;

import org.haox.kerb.codec.kerberos.AuthzDataUtil;
import org.haox.kerb.codec.kerberos.KerberosCredentials;
import org.haox.kerb.codec.kerberos.KerberosTicket;
import org.haox.kerb.codec.kerberos.KerberosToken;
import org.haox.kerb.codec.pac.Pac;
import org.haox.kerb.codec.pac.PacLogonInfo;
import org.haox.kerb.codec.pac.PacSid;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.AuthorizationData;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class TestKerberos {

    private byte[] rc4Token;
    private byte[] desToken;
    private byte[] aes128Token;
    private byte[] aes256Token;
    private byte[] corruptToken;
    private EncryptionKey rc4Key;
    private EncryptionKey desKey;
    private EncryptionKey aes128Key;
    private EncryptionKey aes256Key;
    private EncryptionKey corruptKey;

    @Before
    public void setUp() throws IOException {
        InputStream file;
        byte[] keyData;

        file = this.getClass().getClassLoader().getResourceAsStream("rc4-kerberos-data");
        rc4Token = new byte[file.available()];
        file.read(rc4Token);
        file.close();

        file = this.getClass().getClassLoader().getResourceAsStream("des-kerberos-data");
        desToken = new byte[file.available()];
        file.read(desToken);
        file.close();

        file = this.getClass().getClassLoader().getResourceAsStream("aes128-kerberos-data");
        aes128Token = new byte[file.available()];
        file.read(aes128Token);
        file.close();

        file = this.getClass().getClassLoader().getResourceAsStream("aes256-kerberos-data");
        aes256Token = new byte[file.available()];
        file.read(aes256Token);
        file.close();

        corruptToken = new byte[]{1, 2, 3, 4, 5, 6};

        file = this.getClass().getClassLoader().getResourceAsStream("rc4-key-data");
        keyData = new byte[file.available()];
        file.read(keyData);
        rc4Key = new EncryptionKey(23, keyData, 2);
        file.close();

        file = this.getClass().getClassLoader().getResourceAsStream("des-key-data");
        keyData = new byte[file.available()];
        file.read(keyData);
        desKey = new EncryptionKey(3, keyData, 2);
        file.close();

        file = this.getClass().getClassLoader().getResourceAsStream("aes128-key-data");
        keyData = new byte[file.available()];
        file.read(keyData);
        aes128Key = new EncryptionKey(17, keyData, 2);
        file.close();

        file = this.getClass().getClassLoader().getResourceAsStream("aes256-key-data");
        keyData = new byte[file.available()];
        file.read(keyData);
        aes256Key = new EncryptionKey(18, keyData, 2);
        file.close();

        corruptKey = new EncryptionKey(23, new byte[]{5, 4, 2, 1, 5, 4, 2, 1, 3}, 2);
    }

    @Test
    public void testRc4Ticket() throws KrbException {
        try {
            KerberosToken token = new KerberosToken(rc4Token, rc4Key);

            Assert.assertNotNull(token);
            Assert.assertNotNull(token.getApRequest());

            KerberosTicket ticket = token.getApRequest().getTicket();
            Assert.assertNotNull(ticket);
            Assert.assertEquals("HTTP/server.test.domain.com", ticket.getServerPrincipalName());
            Assert.assertEquals("DOMAIN.COM", ticket.getServerRealm());
            Assert.assertEquals("user.test", ticket.getUserPrincipalName());
            Assert.assertEquals("DOMAIN.COM", ticket.getUserRealm());
        } catch(IOException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void testDesTicket() throws KrbException {
        try {
            KerberosToken token = new KerberosToken(desToken, desKey);

            Assert.assertNotNull(token);
            Assert.assertNotNull(token.getApRequest());

            KerberosTicket ticket = token.getApRequest().getTicket();
            Assert.assertNotNull(ticket);
            Assert.assertEquals("HTTP/server.test.domain.com", ticket.getServerPrincipalName());
            Assert.assertEquals("DOMAIN.COM", ticket.getServerRealm());
            Assert.assertEquals("user.test@domain.com", ticket.getUserPrincipalName());
            Assert.assertEquals("DOMAIN.COM", ticket.getUserRealm());
        } catch(IOException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void testAes128Ticket() {
        KerberosToken token = null;
        try {
            token = new KerberosToken(aes128Token, aes128Key);
            Assert.fail("Should have thrown IOException.");
        } catch(IOException e) {
            Assert.assertNotNull(e);
            Assert.assertNull(token);
        }
    }

    @Test
    public void testAes256Ticket() {
        KerberosToken token = null;
        try {
            token = new KerberosToken(aes256Token, aes256Key);
            Assert.fail("Should have thrown IOException.");
        } catch(IOException e) {
            Assert.assertNotNull(e);
            Assert.assertNull(token);
        }
    }

    @Test
    public void testCorruptTicket() {
        KerberosToken token = null;
        try {
            token = new KerberosToken(corruptToken, rc4Key);
            Assert.fail("Should have thrown IOException.");
        } catch(IOException e) {
            Assert.assertNotNull(e);
            Assert.assertNull(token);
        }
    }

    @Test
    public void testEmptyTicket() {
        KerberosToken token = null;
        try {
            token = new KerberosToken(new byte[0], rc4Key);
            Assert.fail("Should have thrown IOException.");
        } catch(IOException e) {
            Assert.assertNotNull(e);
            Assert.assertNull(token);
        }
    }

    @Test
    public void testNullTicket() {
        KerberosToken token = null;
        try {
            token = new KerberosToken(null, rc4Key);
            Assert.fail("Should have thrown NullPointerException.");
        } catch(IOException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        } catch(NullPointerException e) {
            Assert.assertNotNull(e);
            Assert.assertNull(token);
        }
    }

    @Test
    public void testCorruptKey() {
        KerberosToken token = null;
        try {
            token = new KerberosToken(rc4Token, corruptKey);
            Assert.fail("Should have thrown IOException.");
        } catch(IOException e) {
            Assert.assertNotNull(e);
            Assert.assertNull(token);
        }
    }

    @Test
    public void testNoMatchingKey() {
        KerberosToken token = null;
        try {
            token = new KerberosToken(rc4Token, desKey);
            Assert.fail("Should have thrown IOException.");
        } catch(IOException e) {
            Assert.assertNotNull(e);
            Assert.assertNull(token);
        }
    }

    @Test
    public void testKerberosPac() throws KrbException {
        try {
            KerberosToken token = new KerberosToken(rc4Token, rc4Key);

            Assert.assertNotNull(token);
            Assert.assertNotNull(token.getApRequest());

            KerberosTicket ticket = token.getApRequest().getTicket();
            Assert.assertNotNull(ticket);

            AuthorizationData authzData = ticket.getAuthorizationData();
            Assert.assertNotNull(authzData);
            Assert.assertTrue(authzData.getElements().size() > 0);

            Pac pac = AuthzDataUtil.getPac(authzData,
                    KerberosCredentials.getServerKey1(ticket.getTicket().getEncPart().getKey().getKeyType()));
            Assert.assertNotNull(pac);

            PacLogonInfo logonInfo = pac.getLogonInfo();
            Assert.assertNotNull(logonInfo);

            List<String> sids = new ArrayList<String>();
            if(logonInfo.getGroupSid() != null)
                sids.add(logonInfo.getGroupSid().toString());
            for(PacSid pacSid : logonInfo.getGroupSids())
                sids.add(pacSid.toString());
            for(PacSid pacSid : logonInfo.getExtraSids())
                sids.add(pacSid.toString());
            for(PacSid pacSid : logonInfo.getResourceGroupSids())
                sids.add(pacSid.toString());

            Assert.assertEquals(ticket.getUserPrincipalName(), logonInfo.getUserName());
        } catch(IOException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
    }
}
