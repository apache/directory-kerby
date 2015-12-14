/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/TrustChain.java $
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

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 27-Feb-2006
 */
public class TrustChain {
    private final Set trustMaterial =
        Collections.synchronizedSet(new HashSet());
    private SortedSet x509Certificates = null;
    private KeyStore unifiedKeyStore = null;

    public TrustChain() {
    }

    public synchronized KeyStore getUnifiedKeyStore()
        throws KeyStoreException, IOException, NoSuchAlgorithmException,
        CertificateException {

        // x509Certificates serves as our "cache available" indicator.
        if (x509Certificates != null) {
            return unifiedKeyStore;
        }

        // First, extract all the X509Certificates from this TrustChain.
        this.x509Certificates = new TreeSet(Certificates.COMPARE_BY_EXPIRY);
        Iterator it = trustMaterial.iterator();
        while (it.hasNext()) {
            TrustMaterial tm = (TrustMaterial) it.next();
            KeyStore ks = tm.getKeyStore();
            if (ks != null) {
                Enumeration en = ks.aliases();
                while (en.hasMoreElements()) {
                    String alias = (String) en.nextElement();
                    if (ks.isCertificateEntry(alias)) {
                        X509Certificate cert;
                        cert = (X509Certificate) ks.getCertificate(alias);
                        if (!x509Certificates.contains(cert)) {
                            x509Certificates.add(cert);
                        }
                    }
                }
            }
        }

        // Now that the X509Certificates are extracted, create the unified
        // keystore.
        it = x509Certificates.iterator();
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        int count = 0;
        while (it.hasNext()) {
            X509Certificate cert = (X509Certificate) it.next();
            // The "count" should keep the aliases unique (is that important?)
            String alias = "commons-ssl-" + count;
            ks.setCertificateEntry(alias, cert);
            count++;
        }
        this.unifiedKeyStore = ks;
        return unifiedKeyStore;
    }

    public synchronized void addTrustMaterial(TrustChain tc) {
        this.x509Certificates = null;  // invalidate cache
        if (tc instanceof TrustMaterial) {
            trustMaterial.add(tc);
        }
        // If duplicates are added, the Set will remove them.
        trustMaterial.addAll(tc.trustMaterial);
    }

    public boolean contains(TrustChain tc) {
        if (tc instanceof TrustMaterial) {
            return trustMaterial.contains(tc);
        } else {
            return trustMaterial.containsAll(tc.trustMaterial);
        }
    }

    public boolean contains(X509Certificate cert)
        throws KeyStoreException, IOException, NoSuchAlgorithmException,
        CertificateException {
        return getCertificates().contains(cert);
    }

    public Object getTrustManagerFactory()
        throws NoSuchAlgorithmException, KeyStoreException, IOException,
        CertificateException {
        KeyStore uks = getUnifiedKeyStore();
        if (uks != null) {
            return null;
            //JavaImpl.newTrustManagerFactory(uks);
        } else {
            return null;
        }
    }

    /**
     * @return Array of TrustManager[] - presumably these will be dropped into
     *         a call to SSLContext.init().  Note:  returns null if this
     *         TrustChain doesn't contain anything to trust.
     * @throws java.security.NoSuchAlgorithmException serious problems
     * @throws java.security.KeyStoreException        serious problems
     * @throws java.io.IOException              serious problems
     * @throws java.security.cert.CertificateException     serious problems
     */
    public Object[] getTrustManagers()
        throws NoSuchAlgorithmException, KeyStoreException, IOException,
        CertificateException {
//        Object tmf = getTrustManagerFactory();
        //return tmf != null ? JavaImpl.getTrustManagers(tmf) : null;
        return null;
    }

    /**
     * @return All X509Certificates contained in this TrustChain as a SortedSet.
     *         The X509Certificates are sorted based on expiry date.
     *         <p/>
     *         See org.apache.commons.ssl.Certificates.COMPARE_BY_EXPIRY.
     * @throws java.security.KeyStoreException        serious problems
     * @throws java.io.IOException              serious problems
     * @throws java.security.NoSuchAlgorithmException serious problems
     * @throws java.security.cert.CertificateException     serious problems
     */
    public synchronized SortedSet getCertificates()
        throws KeyStoreException, IOException, NoSuchAlgorithmException,
        CertificateException {
        if (x509Certificates == null) {
            getUnifiedKeyStore();
        }
        return Collections.unmodifiableSortedSet(x509Certificates);
    }

    /**
     * @return Count of all X509Certificates contained in this TrustChain.
     * @throws java.security.KeyStoreException
     * @throws java.io.IOException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.cert.CertificateException
     */
    public synchronized int getSize()
        throws KeyStoreException, IOException, NoSuchAlgorithmException,
        CertificateException {
        return getCertificates().size();
    }

    /**
     * @return Count of all X509Certificates contained in this TrustChain.
     * @throws java.security.KeyStoreException
     * @throws java.io.IOException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.cert.CertificateException
     */
    public synchronized boolean isEmpty()
        throws KeyStoreException, IOException, NoSuchAlgorithmException,
        CertificateException {
        return getCertificates().isEmpty();
    }

    protected boolean containsTrustAll() {
        Iterator it = trustMaterial.iterator();
        while (it.hasNext()) {
            TrustChain tc = (TrustChain) it.next();
            if (tc == this) {
                continue;
            }
            if (tc.containsTrustAll()) {
                return true;
            }
        }
        return false;
    }

}
