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

import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.kerby.kerberos.kerb.preauth.pkinit.CertificateHelper;
import org.junit.Assert;
import org.junit.Test;

public class CryptoTest {

    @Test
    public void testCertificateLoading() throws Exception {
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
        
        // Convert back into an X.509 Certificate
        List<Certificate> certs2 = CertificateHelper.loadCerts(new java.io.ByteArrayInputStream(certBytes));
        Assert.assertEquals(1, certs2.size());
        
        // Now validate the certificate chain
        
        List<X509Certificate> certsPathList = new ArrayList<>(2);
        certsPathList.add((X509Certificate) certs2.get(0));
        List<Certificate> cacerts = CertificateHelper.loadCerts("cacerttest.pem");
        certsPathList.add((X509Certificate) cacerts.get(0));
        
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        CertPath certPath = certificateFactory.generateCertPath(certsPathList);
        
        CertPathValidator cpv = CertPathValidator.getInstance("PKIX");

        TrustAnchor trustAnchor = new TrustAnchor((X509Certificate) cacerts.get(0), null);

        PKIXParameters parameters = new PKIXParameters(Collections.singleton(trustAnchor));
        parameters.setRevocationEnabled(false);

        cpv.validate(certPath, parameters);
    }
}
