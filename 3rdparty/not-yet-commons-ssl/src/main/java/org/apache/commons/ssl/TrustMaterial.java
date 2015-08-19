/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/TrustMaterial.java $
 * $Revision: 171 $
 * $Date: 2014-05-09 08:15:26 -0700 (Fri, 09 May 2014) $
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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 27-Feb-2006
 */
public class TrustMaterial extends TrustChain {
    static final int SIMPLE_TRUST_TYPE_TRUST_ALL = 1;
    static final int SIMPLE_TRUST_TYPE_TRUST_THIS_JVM = 2;

    /**
     * Might be null if "$JAVA_HOME/jre/lib/security/cacerts" doesn't exist.
     */
    public static final TrustMaterial CACERTS;

    /**
     * Might be null if "$JAVA_HOME/jre/lib/security/jssecacerts" doesn't exist.
     */
    public static final TrustMaterial JSSE_CACERTS;

    /**
     * Should never be null (unless both CACERTS and JSSE_CACERTS are not
     * present???).  Is either CACERTS or JSSE_CACERTS.  Priority given to
     * JSSE_CACERTS, but 99.9% of the time it's CACERTS, since JSSE_CACERTS
     * is almost never present.
     */
    public static final TrustMaterial DEFAULT;

    static {
        JavaImpl.load();
        String javaHome = System.getProperty("java.home");
        String pathToCacerts = javaHome + "/lib/security/cacerts";
        String pathToJSSECacerts = javaHome + "/lib/security/jssecacerts";
        TrustMaterial cacerts = null;
        TrustMaterial jssecacerts = null;
        try {
            File f = new File(pathToCacerts);
            if (f.exists()) {
                cacerts = new TrustMaterial(pathToCacerts);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            File f = new File(pathToJSSECacerts);
            if (f.exists()) {
                jssecacerts = new TrustMaterial(pathToJSSECacerts);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        CACERTS = cacerts;
        JSSE_CACERTS = jssecacerts;
        if (JSSE_CACERTS != null) {
            DEFAULT = JSSE_CACERTS;
        } else {
            DEFAULT = CACERTS;
        }
    }

    public static final TrustMaterial TRUST_ALL =
        new TrustMaterial(SIMPLE_TRUST_TYPE_TRUST_ALL);

    public static final TrustMaterial TRUST_THIS_JVM =
        new TrustMaterial(SIMPLE_TRUST_TYPE_TRUST_THIS_JVM);

    public final int simpleTrustType;
    private final KeyStore jks;

    private TrustMaterial(int simpleTrustType) {
        this(null, simpleTrustType);
    }

    TrustMaterial(KeyStore jks, int simpleTrustType) {
        if (jks == null && simpleTrustType != 0) {
            // Just use CACERTS as a place holder, since Java 5 and 6 seem to get
            // upset when we hand SSLContext null TrustManagers.  See
            // Java14.initSSL(), which despite its name, is also used
            // with Java5 and Java6.
            this.jks = CACERTS != null ? CACERTS.jks : JSSE_CACERTS.jks;
        } else {
            this.jks = jks;
        }
        addTrustMaterial(this);
        this.simpleTrustType = simpleTrustType;
    }

    public TrustMaterial(Collection x509Certs)
        throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        loadCerts(ks, x509Certs);
        this.jks = ks;
        addTrustMaterial(this);

        // We're not a simple trust type, so set value to 0.
        // Only TRUST_ALL and TRUST_THIS_JVM are simple trust types.
        this.simpleTrustType = 0;
    }

    public TrustMaterial(X509Certificate x509Cert)
        throws GeneralSecurityException, IOException {
        this(Collections.singleton(x509Cert));
    }

    public TrustMaterial(X509Certificate[] x509Certs)
        throws GeneralSecurityException, IOException {
        this(Arrays.asList(x509Certs));
    }

    public TrustMaterial(byte[] pemBase64)
        throws GeneralSecurityException, IOException {
        this(pemBase64, null);
    }

    public TrustMaterial(InputStream pemBase64)
        throws GeneralSecurityException, IOException {
        this(Util.streamToBytes(pemBase64));
    }

    public TrustMaterial(String pathToPemFile)
        throws GeneralSecurityException, IOException {
        this(new FileInputStream(pathToPemFile));
    }

    public TrustMaterial(File pemFile)
        throws GeneralSecurityException, IOException {
        this(new FileInputStream(pemFile));
    }

    public TrustMaterial(URL urlToPemFile)
        throws GeneralSecurityException, IOException {
        this(urlToPemFile.openStream());
    }

    public TrustMaterial(String pathToJksFile, char[] password)
        throws GeneralSecurityException, IOException {
        this(new File(pathToJksFile), password);
    }

    public TrustMaterial(File jksFile, char[] password)
        throws GeneralSecurityException, IOException {
        this(new FileInputStream(jksFile), password);
    }

    public TrustMaterial(URL urlToJKS, char[] password)
        throws GeneralSecurityException, IOException {
        this(urlToJKS.openStream(), password);
    }

    public TrustMaterial(InputStream jks, char[] password)
        throws GeneralSecurityException, IOException {
        this(Util.streamToBytes(jks), password);
    }

    public TrustMaterial(byte[] jks, char[] password)
        throws GeneralSecurityException, IOException {

        KeyStoreBuilder.BuildResult br;
        br = KeyStoreBuilder.parse(jks, password, null, true);
        if (br.jks != null) {
            // If we've been given a keystore, just use that.
            this.jks = br.jks;
        } else {
            // Otherwise we need to build a keystore from what we were given.
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            if (br.chains != null && !br.chains.isEmpty()) {
                Certificate[] c = (Certificate[]) br.chains.get(0);
                if (c.length > 0) {
                    ks.load(null, password);
                    loadCerts(ks, Arrays.asList(c));
                }
            }
            this.jks = ks;
        }

        // Should validate our keystore to make sure it has at least ONE
        // certificate entry:
        KeyStore ks = this.jks;
        boolean hasCertificates = false;
        Enumeration en = ks.aliases();
        while (en.hasMoreElements()) {
            String alias = (String) en.nextElement();
            if (ks.isCertificateEntry(alias)) {
                hasCertificates = true;
                break;
            }
        }
        if (!hasCertificates) {
            throw new KeyStoreException("TrustMaterial couldn't load any certificates to trust!");
        }

        addTrustMaterial(this);

        // We're not a simple trust type, so set value to 0.
        // Only TRUST_ALL and TRUST_THIS_JVM are simple trust types.
        this.simpleTrustType = 0;
    }

    public KeyStore getKeyStore() {
        return jks;
    }

    private static void loadCerts(KeyStore ks, Collection certs)
        throws KeyStoreException {
        Iterator it = certs.iterator();
        int count = 0;
        while (it.hasNext()) {
            X509Certificate cert = (X509Certificate) it.next();

            // I could be fancy and parse out the CN field from the
            // certificate's subject, but these names don't actually matter
            // at all - I think they just have to be unique.
            String cn = Certificates.getCN(cert);
            String alias = cn + "_" + count;
            ks.setCertificateEntry(alias, cert);
            count++;
        }
    }

    protected boolean containsTrustAll() {
        boolean yes = this.simpleTrustType == SIMPLE_TRUST_TYPE_TRUST_ALL;
        if (!yes) {
            yes = super.containsTrustAll();
        }
        return yes;
    }

}
