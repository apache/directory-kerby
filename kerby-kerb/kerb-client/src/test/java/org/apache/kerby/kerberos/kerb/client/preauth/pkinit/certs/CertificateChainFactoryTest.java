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
package org.apache.kerby.kerberos.kerb.client.preauth.pkinit.certs;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Tests the dynamic generation of certificate chains.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class CertificateChainFactoryTest {

    @Before
    public void setUp() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }


    /**
     * Tests construction of the client chain.
     * <p/>
     * The created certificates can be displayed with a command like:
     * <p/>
     * openssl pkcs12 -nodes -info -in /tmp/test.p12 > /tmp/test.cert && openssl x509 -noout -text -in /tmp/test.cert
     *
     * @throws Exception
     */
    @Test
    public void testClientChain() throws Exception {
        X509Certificate[] clientChain = CertificateChainFactory.getClientChain();

        validateChain(clientChain);
    }


    /**
     * Tests construction of the KDC chain.
     * <p/>
     * The created certificates can be displayed with a command like:
     * <p/>
     * openssl pkcs12 -nodes -info -in /tmp/test.p12 > /tmp/test.cert && openssl x509 -noout -text -in /tmp/test.cert
     *
     * @throws Exception
     */
    @Test
    public void testKdcChain() throws Exception {
        X509Certificate[] kdcChain = CertificateChainFactory.getKdcChain();

        validateChain(kdcChain);
    }


    /**
     * Validates a chain of {@link X509Certificate}s.
     *
     * @param chain
     * @throws CertificateException
     * @throws InvalidAlgorithmParameterException
     */
    private void validateChain(X509Certificate[] chain) throws CertificateException,
            InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException, CertPathValidatorException {
        List<X509Certificate> certificateList = Arrays.asList(chain);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        CertPath certPath = certificateFactory.generateCertPath(certificateList);

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");

        TrustAnchor trustAnchor = new TrustAnchor(chain[chain.length - 1], null);

        PKIXParameters parameters = new PKIXParameters(Collections.singleton(trustAnchor));
        parameters.setRevocationEnabled(false);

        cpv.validate(certPath, parameters);
    }
}
