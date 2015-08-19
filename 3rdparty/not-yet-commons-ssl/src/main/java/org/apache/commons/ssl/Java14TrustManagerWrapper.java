/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/Java14TrustManagerWrapper.java $
 * $Revision: 138 $
 * $Date: 2008-03-03 23:50:07 -0800 (Mon, 03 Mar 2008) $
 *
 * ====================================================================
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */

package org.apache.commons.ssl;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 30-Mar-2006
 */
public class Java14TrustManagerWrapper implements X509TrustManager {
    private final X509TrustManager trustManager;
    private final TrustChain trustChain;
    private final SSL ssl;

    public Java14TrustManagerWrapper(X509TrustManager m, TrustChain tc, SSL h) {
        this.trustManager = m;
        this.trustChain = tc;
        this.ssl = h;
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType)
        throws CertificateException {
        ssl.setCurrentClientChain(chain);
        CertificateException ce = null;
        try {
            trustManager.checkClientTrusted(chain, authType);
        }
        catch (CertificateException e) {
            ce = e;
        }
        testShouldWeThrow(ce, chain);
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType)
        throws CertificateException {
        ssl.setCurrentServerChain(chain);
        CertificateException ce = null;
        try {
            trustManager.checkServerTrusted(chain, authType);
        }
        catch (CertificateException e) {
            ce = e;
        }
        testShouldWeThrow(ce, chain);
    }

    public X509Certificate[] getAcceptedIssuers() {
        if (trustChain.containsTrustAll()) {
            // Counter-intuitively, this means we accept all issuers.
            return new X509Certificate[0];
        } else {
            return trustManager.getAcceptedIssuers();
        }
    }

    private void testShouldWeThrow(CertificateException checkException,
                                   X509Certificate[] chain)
        throws CertificateException {
        if (checkException != null) {
            Throwable root = getRootThrowable(checkException);
            boolean expiryProblem = root instanceof CertificateExpiredException;
            if (expiryProblem) {
                if (ssl.getCheckExpiry()) {
                    // We're expired, and this factory cares.
                    throw checkException;
                }
            } else {
                // Probably the cert isn't trusted.  Only let it through if
                // this factory trusts everything.
                if (!trustChain.contains(TrustMaterial.TRUST_ALL)) {
                    throw checkException;
                }
            }
        }

        for (int i = 0; i < chain.length; i++) {
            X509Certificate c = chain[i];
            if (ssl.getCheckExpiry()) {
                c.checkValidity();
            }
            if (ssl.getCheckCRL()) {
                Certificates.checkCRL(c);
            }
        }
    }

    private static Throwable getRootThrowable(Throwable t) {
        if (t == null) {
            return t;
        }
        Throwable cause = t.getCause();
        while (cause != null && !t.equals(cause)) {
            t = cause;
            cause = t.getCause();
        }
        return t;
    }
}
