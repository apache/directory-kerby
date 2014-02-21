package org.haox.kerb.decoding;

import java.io.IOException;
import java.io.InputStream;

import javax.crypto.spec.SecretKeySpec;

import org.haox.kerb.decoding.pac.Pac;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class TestPac {

    private byte[] rc4Data;
    private byte[] desData;
    private byte[] corruptData;
    private SecretKeySpec rc4Key;
    private SecretKeySpec desKey;
    private SecretKeySpec corruptKey;

    @Before
    public void setUp() throws IOException {
        InputStream file;
        byte[] keyData;

        file = this.getClass().getClassLoader().getResourceAsStream("rc4-pac-data");
        rc4Data = new byte[file.available()];
        file.read(rc4Data);
        file.close();

        file = this.getClass().getClassLoader().getResourceAsStream("des-pac-data");
        desData = new byte[file.available()];
        file.read(desData);
        file.close();

        corruptData = new byte[]{5, 4, 2, 1, 5, 4, 2, 1, 3};

        file = this.getClass().getClassLoader().getResourceAsStream("rc4-key-data");
        keyData = new byte[file.available()];
        file.read(keyData);
        rc4Key = new SecretKeySpec(keyData, "ArcFourHmac");
        file.close();

        file = this.getClass().getClassLoader().getResourceAsStream("des-key-data");
        keyData = new byte[file.available()];
        file.read(keyData);
        desKey = new SecretKeySpec(keyData, "DES");
        file.close();

        corruptKey = new SecretKeySpec(new byte[]{5, 4, 2, 1, 5, 4, 2, 1, 3}, "");
    }

    @Test
    public void testRc4Pac() {
        try {
            Pac pac = new Pac(rc4Data, rc4Key);

            Assert.assertNotNull(pac);
            Assert.assertNotNull(pac.getLogonInfo());

            Assert.assertEquals("user.test", pac.getLogonInfo().getUserName());
            Assert.assertEquals("User Test", pac.getLogonInfo().getUserDisplayName());
            Assert.assertEquals(0, pac.getLogonInfo().getBadPasswordCount());
            Assert.assertEquals(32, pac.getLogonInfo().getUserFlags());
            Assert.assertEquals(46, pac.getLogonInfo().getLogonCount());
            Assert.assertEquals("DOMAIN", pac.getLogonInfo().getDomainName());
            Assert.assertEquals("WS2008", pac.getLogonInfo().getServerName());

        } catch(DecodingException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void testDesPac() {
        try {
            Pac pac = new Pac(desData, desKey);

            Assert.assertNotNull(pac);
            Assert.assertNotNull(pac.getLogonInfo());

            Assert.assertEquals("user.test", pac.getLogonInfo().getUserName());
            Assert.assertEquals("User Test", pac.getLogonInfo().getUserDisplayName());
            Assert.assertEquals(0, pac.getLogonInfo().getBadPasswordCount());
            Assert.assertEquals(32, pac.getLogonInfo().getUserFlags());
            Assert.assertEquals(48, pac.getLogonInfo().getLogonCount());
            Assert.assertEquals("DOMAIN", pac.getLogonInfo().getDomainName());
            Assert.assertEquals("WS2008", pac.getLogonInfo().getServerName());

        } catch(DecodingException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void testCorruptPac() {
        Pac pac = null;
        try {
            pac = new Pac(corruptData, rc4Key);
            Assert.fail("Should have thrown DecodingException.");
        } catch(DecodingException e) {
            Assert.assertNotNull(e);
            Assert.assertNull(pac);
        }
    }

    @Test
    public void testEmptyPac() {
        Pac pac = null;
        try {
            pac = new Pac(new byte[0], rc4Key);
            Assert.fail("Should have thrown DecodingException.");
        } catch(DecodingException e) {
            Assert.assertNotNull(e);
            Assert.assertNull(pac);
        }
    }

    @Test
    public void testNullPac() {
        Pac pac = null;
        try {
            pac = new Pac(null, rc4Key);
            Assert.fail("Should have thrown NullPointerException.");
        } catch(DecodingException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        } catch(NullPointerException e) {
            Assert.assertNotNull(e);
            Assert.assertNull(pac);
        }
    }

    @Test
    public void testCorruptKey() {
        Pac pac = null;
        try {
            pac = new Pac(rc4Data, corruptKey);
            Assert.fail("Should have thrown DecodingException.");
        } catch(DecodingException e) {
            Assert.assertNotNull(e);
            Assert.assertNull(pac);
        }
    }
}
