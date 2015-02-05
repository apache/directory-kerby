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

import java.io.IOException;
import java.io.InputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Fail.fail;

public class TestSpnego {

    private byte[] rc4Token;
    private byte[] desToken;
    private byte[] aes128Token;
    private byte[] aes256Token;
    private byte[] corruptToken;

    //@Before
    public void setUp() throws IOException {

        InputStream file = this.getClass().getClassLoader().getResourceAsStream("rc4-spnego-data");
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

            assertThat(spnegoToken).isNotNull();
            assertThat(spnegoToken instanceof SpnegoInitToken).isTrue();
            assertThat(spnegoToken.getMechanismToken()).isNotNull();
            assertThat(spnegoToken.getMechanismToken().length < rc4Token.length).isTrue();
            assertThat(spnegoToken.getMechanism()).isNotNull();
            assertThat(spnegoToken.getMechanism()).isEqualTo(SpnegoConstants.LEGACY_KERBEROS_MECHANISM);
        } catch(IOException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    //@Test
    public void testDesToken() {
        try {
            SpnegoToken spnegoToken = SpnegoToken.parse(desToken);

            assertThat(spnegoToken).isNotNull();
            assertThat(spnegoToken instanceof SpnegoInitToken).isTrue();
            assertThat(spnegoToken.getMechanismToken()).isNotNull();
            assertThat(spnegoToken.getMechanismToken().length < desToken.length).isTrue();
            assertThat(spnegoToken.getMechanism()).isNotNull();
            assertThat(spnegoToken.getMechanism()).isEqualTo(SpnegoConstants.LEGACY_KERBEROS_MECHANISM);
        } catch(IOException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    //@Test
    public void testAes128Token() {
        try {
            SpnegoToken spnegoToken = SpnegoToken.parse(aes128Token);

            assertThat(spnegoToken).isNotNull();
            assertThat(spnegoToken instanceof SpnegoInitToken).isTrue();
            assertThat(spnegoToken.getMechanismToken()).isNotNull();
            assertThat(spnegoToken.getMechanismToken().length < aes128Token.length).isTrue();
            assertThat(spnegoToken.getMechanism()).isNotNull();
            assertThat(spnegoToken.getMechanism()).isEqualTo(SpnegoConstants.LEGACY_KERBEROS_MECHANISM);
        } catch(IOException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    //@Test
    public void testAes256Token() {
        try {
            SpnegoToken spnegoToken = SpnegoToken.parse(aes256Token);

            assertThat(spnegoToken).isNotNull();
            assertThat(spnegoToken instanceof SpnegoInitToken).isTrue();
            assertThat(spnegoToken.getMechanismToken()).isNotNull();
            assertThat(spnegoToken.getMechanismToken().length < aes256Token.length).isTrue();
            assertThat(spnegoToken.getMechanism()).isNotNull();
            assertThat(spnegoToken.getMechanism()).isEqualTo(SpnegoConstants.LEGACY_KERBEROS_MECHANISM);
        } catch(IOException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    //@Test
    public void testEmptyToken() {
        SpnegoToken spnegoToken = null;
        try {
            spnegoToken = SpnegoToken.parse(new byte[0]);
            fail("Should have thrown DecodingException.");
        } catch(IOException e) {
            assertThat(e).isNotNull();
            assertThat(spnegoToken).isNull();
        }
    }

    //@Test
    public void testCorruptToken() {
        SpnegoToken spnegoToken = null;
        try {
            spnegoToken = SpnegoToken.parse(corruptToken);
            fail("Should have thrown DecodingException.");
        } catch(IOException e) {
            assertThat(e).isNotNull();
            assertThat(spnegoToken).isNull();
        }
    }

    //@Test
    public void testNullToken() {
        SpnegoToken spnegoToken = null;
        try {
            spnegoToken = SpnegoToken.parse(null);
            fail("Should have thrown NullPointerException.");
        } catch(IOException e) {
            e.printStackTrace();
            fail(e.getMessage());
        } catch(NullPointerException e) {
            assertThat(e).isNotNull();
            assertThat(spnegoToken).isNull();
        }
    }

}
