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
package org.apache.kerby.kerberos.kerb;

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.List;

import org.apache.kerby.kerberos.kerb.preauth.pkinit.CertificateHelper;
import org.junit.Assert;
import org.junit.Test;

public class CryptoTest {

    @Test
    @org.junit.Ignore
    public void testCertificateLoading() throws IOException, KrbException, CertificateEncodingException {
        // Load cert
        List<Certificate> certs = CertificateHelper.loadCerts("kdccerttest.pem");
        Assert.assertEquals(1, certs.size());
        
        // Now convert to a Kerby Certificate type
        org.apache.kerby.x509.type.Certificate certificate = new org.apache.kerby.x509.type.Certificate();
        byte[] encodedBytes = certs.get(0).getEncoded();
        certificate.decode(encodedBytes);
        Assert.assertNotNull(certificate);
        
        // Now convert back to an X.509 Certificate
        byte[] certBytes = certificate.encode();
        
        // Test for equality
        Assert.assertArrayEquals(certBytes, encodedBytes);
    }
}
