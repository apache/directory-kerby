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
package org.apache.kerby.x509;

import org.apache.kerby.pki.PkiLoader;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 openssl genrsa -out cakey.pem 2048
 openssl req -key cakey.pem -new -x509 -out cacert.pem -days 3650
 vi extensions.kdc
 openssl genrsa -out kdckey.pem 2048
 openssl req -new -out kdc.req -key kdckey.pem
 env REALM=SH.INTEL.COM openssl x509 -req -in kdc.req -CAkey cakey.pem \
 -CA cacert.pem -out kdc.pem -days 365 -extfile extensions.kdc -extensions kdc_cert -CAcreateserial
 */
public class PkiLoaderTest {
    private PkiLoader pkiLoader;

    @Before
    public void setup() {
        pkiLoader = new PkiLoader();
    }

    @Test
    public void loadCert() throws IOException {
        InputStream res = getClass().getResourceAsStream("/usercert.pem");
        List<Certificate> certs = pkiLoader.loadCerts(res);
        Certificate userCert = certs.iterator().next();

        assertThat(userCert).isNotNull();
    }

    @Test
    public void loadKey() throws IOException {
        InputStream res = getClass().getResourceAsStream("/userkey.pem");
        PrivateKey key = pkiLoader.loadPrivateKey(res, null);

        assertThat(key).isNotNull();
    }
}