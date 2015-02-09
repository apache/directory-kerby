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

import org.apache.kerby.kerberos.kerb.codec.kerberos.KerberosTicket;
import org.apache.kerby.kerberos.kerb.codec.kerberos.KerberosToken;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionKey;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

public class TestKerberos {

    private byte[] rc4Token;
    private byte[] desToken;
    private byte[] aes128Token;
    private byte[] aes256Token;
    private EncryptionKey rc4Key;
    private EncryptionKey desKey;
    private EncryptionKey aes128Key;
    private EncryptionKey aes256Key;

    @Before
    public void setUp() throws IOException {

        InputStream file = this.getClass().getClassLoader().getResourceAsStream("rc4-kerberos-data");
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

        file = this.getClass().getClassLoader().getResourceAsStream("rc4-key-data");
        byte[] keyData = new byte[file.available()];
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
    }

    @Test
    public void testRc4Ticket() throws Exception {
        KerberosToken token = new KerberosToken(rc4Token, rc4Key);

        assertThat(token).isNotNull();
        assertThat(token.getApRequest()).isNotNull();

        KerberosTicket ticket = token.getApRequest().getTicket();
        assertThat(ticket).isNotNull();
        assertThat(ticket.getServerPrincipalName()).isEqualTo("HTTP/server.test.domain.com");
        assertThat(ticket.getServerRealm()).isEqualTo("DOMAIN.COM");
        assertThat(ticket.getUserPrincipalName()).isEqualTo("user.test");
        assertThat(ticket.getUserRealm()).isEqualTo("DOMAIN.COM");
    }

    //@Test
    public void testDesTicket() throws Exception {
        KerberosToken token = new KerberosToken(desToken, desKey);

        assertThat(token).isNotNull();
        assertThat(token.getApRequest()).isNotNull();

        KerberosTicket ticket = token.getApRequest().getTicket();
        assertThat(ticket).isNotNull();
        assertThat(ticket.getServerPrincipalName()).isEqualTo("HTTP/server.test.domain.com");
        assertThat(ticket.getServerRealm()).isEqualTo("DOMAIN.COM");
        assertThat(ticket.getUserPrincipalName()).isEqualTo("user.test@domain.com");
        assertThat(ticket.getUserRealm()).isEqualTo("DOMAIN.COM");
    }

    @Test
    public void testAes128Ticket() throws Exception {
        KerberosToken token = null;
        token = new KerberosToken(aes128Token, aes128Key);

        assertThat(token).isNotNull();
        assertThat(token.getApRequest()).isNotNull();

        KerberosTicket ticket = token.getApRequest().getTicket();
        assertThat(ticket).isNotNull();
        assertThat(ticket.getServerPrincipalName()).isEqualTo("HTTP/server.test.domain.com");
        assertThat(ticket.getServerRealm()).isEqualTo("DOMAIN.COM");
        assertThat(ticket.getUserPrincipalName()).isEqualTo("user.test");
        assertThat(ticket.getUserRealm()).isEqualTo("DOMAIN.COM");
    }

    @Test
    public void testAes256Ticket() throws Exception {
        KerberosToken token = null;
        token = new KerberosToken(aes256Token, aes256Key);

        assertThat(token).isNotNull();
        assertThat(token.getApRequest()).isNotNull();

        KerberosTicket ticket = token.getApRequest().getTicket();
        assertThat(ticket).isNotNull();
        assertThat(ticket.getServerPrincipalName()).isEqualTo("HTTP/server.test.domain.com");
        assertThat(ticket.getServerRealm()).isEqualTo("DOMAIN.COM");
        assertThat(ticket.getUserPrincipalName()).isEqualTo("user.test");
        assertThat(ticket.getUserRealm()).isEqualTo("DOMAIN.COM");
    }

    @Test
    public void testNoMatchingKey() {
        KerberosToken token = null;
        try {
            token = new KerberosToken(rc4Token, desKey);
            fail("Should have thrown Exception.");
        } catch(Exception e) {
            assertThat(e).isNotNull();
            assertThat(token).isNull();
        }
    }
}
