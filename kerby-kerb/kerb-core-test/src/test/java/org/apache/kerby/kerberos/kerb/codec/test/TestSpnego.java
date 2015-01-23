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
package org.apache.kerby.kerberos.kerb.codec.test;

import org.apache.kerby.kerberos.kerb.codec.spnego.SpnegoConstants;
import org.apache.kerby.kerberos.kerb.codec.spnego.SpnegoInitToken;
import org.apache.kerby.kerberos.kerb.codec.spnego.SpnegoToken;
import org.junit.Assert;

import java.io.IOException;
import java.io.InputStream;

public class TestSpnego {

    private byte[] rc4Token;
    private byte[] desToken;
    private byte[] aes128Token;
    private byte[] aes256Token;
    private byte[] corruptToken;

    //@Before
    public void setUp() throws IOException {
        InputStream file;

        file = this.getClass().getClassLoader().getResourceAsStream("rc4-spnego-data");
        rc4Token = new byte[file.available()];
        file.read(rc4Token);
        file.close();

        file = this.getClass().getClassLoader().getResourceAsStream("des-spnego-data");
        desToken = new byte[file.available()];
        file.read(desToken);
        file.close();

        file = this.getClass().getClassLoader().getResourceAsStream("aes128-spnego-data");
        aes128Token = new byte[file.available()];
        file.read(aes128Token);
        file.close();

        file = this.getClass().getClassLoader().getResourceAsStream("aes256-spnego-data");
        aes256Token = new byte[file.available()];
        file.read(aes256Token);
        file.close();

        corruptToken = new byte[]{5, 4, 2, 1};
    }

    //@Test
    public void testRc4Token() {
        try {
            SpnegoToken spnegoToken = SpnegoToken.parse(rc4Token);

            Assert.assertNotNull(spnegoToken);
            Assert.assertTrue(spnegoToken instanceof SpnegoInitToken);
            Assert.assertNotNull(spnegoToken.getMechanismToken());
            Assert.assertTrue(spnegoToken.getMechanismToken().length < rc4Token.length);
            Assert.assertNotNull(spnegoToken.getMechanism());
            Assert.assertEquals(SpnegoConstants.LEGACY_KERBEROS_MECHANISM, spnegoToken.getMechanism());
        } catch(IOException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
    }

    //@Test
    public void testDesToken() {
        try {
            SpnegoToken spnegoToken = SpnegoToken.parse(desToken);

            Assert.assertNotNull(spnegoToken);
            Assert.assertTrue(spnegoToken instanceof SpnegoInitToken);
            Assert.assertNotNull(spnegoToken.getMechanismToken());
            Assert.assertTrue(spnegoToken.getMechanismToken().length < desToken.length);
            Assert.assertNotNull(spnegoToken.getMechanism());
            Assert.assertEquals(SpnegoConstants.LEGACY_KERBEROS_MECHANISM, spnegoToken.getMechanism());
        } catch(IOException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
    }

    //@Test
    public void testAes128Token() {
        try {
            SpnegoToken spnegoToken = SpnegoToken.parse(aes128Token);

            Assert.assertNotNull(spnegoToken);
            Assert.assertTrue(spnegoToken instanceof SpnegoInitToken);
            Assert.assertNotNull(spnegoToken.getMechanismToken());
            Assert.assertTrue(spnegoToken.getMechanismToken().length < aes128Token.length);
            Assert.assertNotNull(spnegoToken.getMechanism());
            Assert.assertEquals(SpnegoConstants.LEGACY_KERBEROS_MECHANISM, spnegoToken.getMechanism());
        } catch(IOException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
    }

    //@Test
    public void testAes256Token() {
        try {
            SpnegoToken spnegoToken = SpnegoToken.parse(aes256Token);

            Assert.assertNotNull(spnegoToken);
            Assert.assertTrue(spnegoToken instanceof SpnegoInitToken);
            Assert.assertNotNull(spnegoToken.getMechanismToken());
            Assert.assertTrue(spnegoToken.getMechanismToken().length < aes256Token.length);
            Assert.assertNotNull(spnegoToken.getMechanism());
            Assert.assertEquals(SpnegoConstants.LEGACY_KERBEROS_MECHANISM, spnegoToken.getMechanism());
        } catch(IOException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
    }

    //@Test
    public void testEmptyToken() {
        SpnegoToken spnegoToken = null;
        try {
            spnegoToken = SpnegoToken.parse(new byte[0]);
            Assert.fail("Should have thrown DecodingException.");
        } catch(IOException e) {
            Assert.assertNotNull(e);
            Assert.assertNull(spnegoToken);
        }
    }

    //@Test
    public void testCorruptToken() {
        SpnegoToken spnegoToken = null;
        try {
            spnegoToken = SpnegoToken.parse(corruptToken);
            Assert.fail("Should have thrown DecodingException.");
        } catch(IOException e) {
            Assert.assertNotNull(e);
            Assert.assertNull(spnegoToken);
        }
    }

    //@Test
    public void testNullToken() {
        SpnegoToken spnegoToken = null;
        try {
            spnegoToken = SpnegoToken.parse(null);
            Assert.fail("Should have thrown NullPointerException.");
        } catch(IOException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        } catch(NullPointerException e) {
            Assert.assertNotNull(e);
            Assert.assertNull(spnegoToken);
        }
    }

}
