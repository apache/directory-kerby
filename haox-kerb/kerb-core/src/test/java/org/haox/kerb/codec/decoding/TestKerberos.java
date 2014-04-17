package org.haox.kerb.codec.decoding;

import org.haox.kerb.codec.DecodingException;
import org.haox.kerb.codec.kerberos.KerberosTicket;
import org.haox.kerb.codec.kerberos.KerberosToken;
import org.haox.kerb.codec.kerberos.KerberosPacAuthData;
import org.haox.kerb.codec.pac.Pac;
import org.haox.kerb.codec.pac.PacLogonInfo;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.AuthorizationData;
import org.haox.kerb.spec.type.common.AuthorizationDataEntry;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import javax.security.auth.kerberos.KerberosKey;
import java.io.IOException;
import java.io.InputStream;

public class TestKerberos {

    private byte[] rc4Token;
    private byte[] desToken;
    private byte[] aes128Token;
    private byte[] aes256Token;
    private byte[] corruptToken;
    private KerberosKey rc4Keys[];
    private KerberosKey desKeys[];
    private KerberosKey aes128Keys[];
    private KerberosKey aes256Keys[];
    private KerberosKey corruptKeys[];

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
        rc4Keys = new KerberosKey[]{new KerberosKey(null, keyData, 23, 2)};
        file.close();

        file = this.getClass().getClassLoader().getResourceAsStream("des-key-data");
        keyData = new byte[file.available()];
        file.read(keyData);
        desKeys = new KerberosKey[]{new KerberosKey(null, keyData, 3, 2)};
        file.close();

        file = this.getClass().getClassLoader().getResourceAsStream("aes128-key-data");
        keyData = new byte[file.available()];
        file.read(keyData);
        aes128Keys = new KerberosKey[]{new KerberosKey(null, keyData, 17, 2)};
        file.close();

        file = this.getClass().getClassLoader().getResourceAsStream("aes256-key-data");
        keyData = new byte[file.available()];
        file.read(keyData);
        aes256Keys = new KerberosKey[]{new KerberosKey(null, keyData, 18, 2)};
        file.close();

        corruptKeys = new KerberosKey[]{new KerberosKey(null,
                new byte[]{5, 4, 2, 1, 5, 4, 2, 1, 3}, 23, 2)};
    }

    @Test
    public void testRc4Ticket() throws KrbException {
        try {
            KerberosToken token = new KerberosToken(rc4Token, rc4Keys);

            Assert.assertNotNull(token);
            Assert.assertNotNull(token.getApRequest());

            KerberosTicket ticket = token.getApRequest().getTicket();
            Assert.assertNotNull(ticket);
            Assert.assertEquals("HTTP/server.test.domain.com", ticket.getServerPrincipalName());
            Assert.assertEquals("DOMAIN.COM", ticket.getServerRealm());
            Assert.assertEquals("user.test", ticket.getUserPrincipalName());
            Assert.assertEquals("DOMAIN.COM", ticket.getUserRealm());
        } catch(DecodingException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void testDesTicket() throws KrbException {
        try {
            KerberosToken token = new KerberosToken(desToken, desKeys);

            Assert.assertNotNull(token);
            Assert.assertNotNull(token.getApRequest());

            KerberosTicket ticket = token.getApRequest().getTicket();
            Assert.assertNotNull(ticket);
            Assert.assertEquals("HTTP/server.test.domain.com", ticket.getServerPrincipalName());
            Assert.assertEquals("DOMAIN.COM", ticket.getServerRealm());
            Assert.assertEquals("user.test@domain.com", ticket.getUserPrincipalName());
            Assert.assertEquals("DOMAIN.COM", ticket.getUserRealm());
        } catch(DecodingException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void testAes128Ticket() {
        KerberosToken token = null;
        try {
            token = new KerberosToken(aes128Token, aes128Keys);
            Assert.fail("Should have thrown DecodingException.");
        } catch(DecodingException e) {
            Assert.assertNotNull(e);
            Assert.assertNull(token);
        }
    }

    @Test
    public void testAes256Ticket() {
        KerberosToken token = null;
        try {
            token = new KerberosToken(aes256Token, aes256Keys);
            Assert.fail("Should have thrown DecodingException.");
        } catch(DecodingException e) {
            Assert.assertNotNull(e);
            Assert.assertNull(token);
        }
    }

    @Test
    public void testCorruptTicket() {
        KerberosToken token = null;
        try {
            token = new KerberosToken(corruptToken, rc4Keys);
            Assert.fail("Should have thrown DecodingException.");
        } catch(DecodingException e) {
            Assert.assertNotNull(e);
            Assert.assertNull(token);
        }
    }

    @Test
    public void testEmptyTicket() {
        KerberosToken token = null;
        try {
            token = new KerberosToken(new byte[0], rc4Keys);
            Assert.fail("Should have thrown DecodingException.");
        } catch(DecodingException e) {
            Assert.assertNotNull(e);
            Assert.assertNull(token);
        }
    }

    @Test
    public void testNullTicket() {
        KerberosToken token = null;
        try {
            token = new KerberosToken(null, rc4Keys);
            Assert.fail("Should have thrown NullPointerException.");
        } catch(DecodingException e) {
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
            token = new KerberosToken(rc4Token, corruptKeys);
            Assert.fail("Should have thrown DecodingException.");
        } catch(DecodingException e) {
            Assert.assertNotNull(e);
            Assert.assertNull(token);
        }
    }

    @Test
    public void testNoMatchingKey() {
        KerberosToken token = null;
        try {
            token = new KerberosToken(rc4Token, desKeys);
            Assert.fail("Should have thrown DecodingException.");
        } catch(DecodingException e) {
            Assert.assertNotNull(e);
            Assert.assertNull(token);
        }
    }

    @Test
    public void testKerberosPac() throws KrbException {
        try {
            KerberosToken token = new KerberosToken(rc4Token, rc4Keys);

            Assert.assertNotNull(token);
            Assert.assertNotNull(token.getApRequest());

            KerberosTicket ticket = token.getApRequest().getTicket();
            Assert.assertNotNull(ticket);

            AuthorizationData authzData = ticket.getAuthorizationData();
            Assert.assertNotNull(authzData);
            Assert.assertTrue(authzData.getEntries().size() > 0);

            if (false) {
                Pac pac = null;
                for(AuthorizationDataEntry authData : authzData.getEntries()) {
                    if(authData instanceof KerberosPacAuthData)
                        pac = ((KerberosPacAuthData)authData).getPac();
                }
                Assert.assertNotNull(pac);

                PacLogonInfo logonInfo = pac.getLogonInfo();
                Assert.assertNotNull(logonInfo);

                Assert.assertEquals(ticket.getUserPrincipalName(), logonInfo.getUserName());
            }
        } catch(DecodingException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
    }
}
