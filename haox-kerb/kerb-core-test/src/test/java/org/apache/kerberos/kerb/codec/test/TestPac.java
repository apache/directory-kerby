/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.kerberos.kerb.codec.test;

import org.apache.kerberos.kerb.KrbException;
import org.apache.kerberos.kerb.codec.pac.Pac;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;

public class TestPac {

    private byte[] rc4Data;
    private byte[] desData;
    private byte[] corruptData;
    private byte[] rc4Key;
    private byte[] desKey;
    private byte[] corruptKey;

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
        rc4Key = keyData;
        file.close();

        file = this.getClass().getClassLoader().getResourceAsStream("des-key-data");
        keyData = new byte[file.available()];
        file.read(keyData);
        desKey = keyData;
        file.close();

        corruptKey = new byte[]{5, 4, 2, 1, 5, 4, 2, 1, 3};
    }

    @Test
    public void testRc4Pac() throws KrbException {
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
    }

    @Test
    public void testDesPac() throws KrbException {
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
    }

    @Test
    public void testCorruptPac() {
        Pac pac = null;
        try {
            pac = new Pac(corruptData, rc4Key);
            Assert.fail("Should have thrown KrbException.");
        } catch(KrbException e) {
            Assert.assertNotNull(e);
            Assert.assertNull(pac);
        }
    }

    @Test
    public void testEmptyPac() {
        Pac pac = null;
        try {
            pac = new Pac(new byte[0], rc4Key);
            Assert.fail("Should have thrown KrbException.");
        } catch(KrbException e) {
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
        } catch(KrbException e) {
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
            Assert.fail("Should have thrown KrbException.");
        } catch(KrbException e) {
            Assert.assertNotNull(e);
            Assert.assertNull(pac);
        }
    }
}
