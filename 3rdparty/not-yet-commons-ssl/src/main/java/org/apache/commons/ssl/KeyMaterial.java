/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/KeyMaterial.java $
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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 27-Feb-2006
 */
public class KeyMaterial extends TrustMaterial {
    private final Object keyManagerFactory;
    private final List aliases;
    private final List associatedChains;

    public KeyMaterial(InputStream jks, char[] password)
        throws GeneralSecurityException, IOException {
        this(Util.streamToBytes(jks), password);
    }

    public KeyMaterial(InputStream jks, char[] jksPass, char[] keyPass)
        throws GeneralSecurityException, IOException {
        this(Util.streamToBytes(jks), jksPass, keyPass);
    }

    public KeyMaterial(InputStream jks, InputStream key, char[] password)
        throws GeneralSecurityException, IOException {
        this(Util.streamToBytes(jks), Util.streamToBytes(key), password);
    }

    public KeyMaterial(InputStream jks, InputStream key, char[] jksPass,
                       char[] keyPass)
        throws GeneralSecurityException, IOException {
        this(Util.streamToBytes(jks), Util.streamToBytes(key), jksPass, keyPass);
    }

    public KeyMaterial(String pathToJksFile, char[] password)
        throws GeneralSecurityException, IOException {
        this(new File(pathToJksFile), password);
    }

    public KeyMaterial(String pathToJksFile, char[] jksPass, char[] keyPass)
        throws GeneralSecurityException, IOException {
        this(new File(pathToJksFile), jksPass, keyPass);
    }

    public KeyMaterial(String pathToCerts, String pathToKey, char[] password)
        throws GeneralSecurityException, IOException {
        this(pathToCerts != null ? new File(pathToCerts) : null,
            pathToKey != null ? new File(pathToKey) : null,
            password);
    }

    public KeyMaterial(String pathToCerts, String pathToKey, char[] jksPass,
                       char[] keyPass)
        throws GeneralSecurityException, IOException {
        this(pathToCerts != null ? new File(pathToCerts) : null,
            pathToKey != null ? new File(pathToKey) : null,
            jksPass, keyPass);
    }

    public KeyMaterial(File jksFile, char[] password)
        throws GeneralSecurityException, IOException {
        this(new FileInputStream(jksFile), password);
    }

    public KeyMaterial(File jksFile, char[] jksPass, char[] keyPass)
        throws GeneralSecurityException, IOException {
        this(new FileInputStream(jksFile), jksPass, keyPass);
    }

    public KeyMaterial(File certsFile, File keyFile, char[] password)
        throws GeneralSecurityException, IOException {
        this(certsFile != null ? new FileInputStream(certsFile) : null,
            keyFile != null ? new FileInputStream(keyFile) : null,
            password);
    }

    public KeyMaterial(File certsFile, File keyFile, char[] jksPass,
                       char[] keyPass)
        throws GeneralSecurityException, IOException {
        this(certsFile != null ? new FileInputStream(certsFile) : null,
            keyFile != null ? new FileInputStream(keyFile) : null,
            jksPass, keyPass);
    }

    public KeyMaterial(URL urlToJKS, char[] password)
        throws GeneralSecurityException, IOException {
        this(urlToJKS.openStream(), password);
    }

    public KeyMaterial(URL urlToJKS, char[] jksPass, char[] keyPass)
        throws GeneralSecurityException, IOException {
        this(urlToJKS.openStream(), jksPass, keyPass);
    }

    public KeyMaterial(URL urlToCerts, URL urlToKey, char[] password)
        throws GeneralSecurityException, IOException {
        this(urlToCerts.openStream(), urlToKey.openStream(), password);
    }

    public KeyMaterial(URL urlToCerts, URL urlToKey, char[] jksPass,
                       char[] keyPass)
        throws GeneralSecurityException, IOException {
        this(urlToCerts.openStream(), urlToKey.openStream(), jksPass, keyPass);
    }

    public KeyMaterial(byte[] jks, char[] password)
        throws GeneralSecurityException, IOException {
        this(jks, (byte[]) null, password);
    }

    public KeyMaterial(byte[] jks, char[] jksPass, char[] keyPass)
        throws GeneralSecurityException, IOException {
        this(jks, null, jksPass, keyPass);
    }

    public KeyMaterial(byte[] jksOrCerts, byte[] key, char[] password)
        throws GeneralSecurityException, IOException {
        this(jksOrCerts, key, password, password);
    }


    public KeyMaterial(byte[] jksOrCerts, byte[] key, char[] jksPass,
                       char[] keyPass)
        throws GeneralSecurityException, IOException {
        // We're not a simple trust type, so set "simpleTrustType" value to 0.
        // Only TRUST_ALL and TRUST_THIS_JVM are simple trust types.
        super(KeyStoreBuilder.build(jksOrCerts, key, jksPass, keyPass), 0);
        KeyStore ks = getKeyStore();
        Enumeration en = ks.aliases();
        List myAliases = new LinkedList();
        List myChains = new LinkedList();
        while (en.hasMoreElements()) {
            X509Certificate[] c; // chain
            String alias = (String) en.nextElement();
            if (ks.isKeyEntry(alias)) {
                try {
                    ks.getKey(alias, keyPass);
                    // No Exception thrown, so we're good!
                    myAliases.add(alias);
                    Certificate[] chain = ks.getCertificateChain(alias);
                    if (chain != null) {
                        c = Certificates.x509ifyChain(chain);
                        // Cleanup chain to remove any spurious entries.
                        if (c != null) {
                            X509Certificate l = c[0]; // The leaf node.
                            c = X509CertificateChainBuilder.buildPath(l, c);
                        }
                        myChains.add(c);
                    } else {
                        throw new KeyStoreException("Could not find KeyMaterial's associated"
                            + "certificate chain with alis=[" + alias + "]");
                    }

                } catch (GeneralSecurityException gse) {
                    // oh well, we can't use that KeyStore alias.
                    gse.printStackTrace();
                }
            }
        }
        if (myAliases.isEmpty()) {
            throw new KeyStoreException("KeyMaterial provided does not contain any keys!");
        }
        this.aliases = Collections.unmodifiableList(myAliases);
        this.associatedChains = Collections.unmodifiableList(myChains);
        this.keyManagerFactory = JavaImpl.newKeyManagerFactory(ks, keyPass);
    }

    public Object[] getKeyManagers() {
        return JavaImpl.getKeyManagers(keyManagerFactory);
    }

    public List getAssociatedCertificateChains() {
        return associatedChains;
    }

    public KeyStore getKeyStore() {
        return super.getKeyStore();
    }

    public List getAliases() {
        return aliases;
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println(
                "Usage1:  java org.apache.commons.ssl.KeyMaterial [password] [pkcs12 or jks]");
            System.out.println(
                "Usage2:  java org.apache.commons.ssl.KeyMaterial [password] [private-key] [cert-chain]");
            System.exit(1);
        }
        char[] jksPass = args[0].toCharArray();
        char[] keyPass = jksPass;
        String path1 = args[1];
        String path2 = null;
        if (args.length >= 3) {
            path2 = args[2];
        }
        if (args.length >= 4) {
            keyPass = args[3].toCharArray();
        } else if (path2 != null) {
            File f = new File(path2);
            if (!f.exists()) {
                // Hmmm... maybe it's a password.
                keyPass = path2.toCharArray();
                path2 = null;
            }
        }

        KeyMaterial km = new KeyMaterial(path1, path2, jksPass, keyPass);
        System.out.println(km);
    }

    public String toString() {
        List chains = getAssociatedCertificateChains();
        List aliases = getAliases();
        Iterator it = chains.iterator();
        Iterator aliasesIt = aliases.iterator();
        StringBuffer buf = new StringBuffer(8192);
        while (it.hasNext()) {
            X509Certificate[] certs = (X509Certificate[]) it.next();
            String alias = (String) aliasesIt.next();
            buf.append("Alias: ");
            buf.append(alias);
            buf.append('\n');
            if (certs != null) {
                for (int i = 0; i < certs.length; i++) {
                    buf.append(Certificates.toString(certs[i]));
                    try {
                        buf.append(Certificates.toPEMString(certs[i]));
                    } catch (CertificateEncodingException cee) {
                        buf.append(cee.toString());
                        buf.append('\n');
                    }
                }
            }
        }
        return buf.toString();
    }
}
