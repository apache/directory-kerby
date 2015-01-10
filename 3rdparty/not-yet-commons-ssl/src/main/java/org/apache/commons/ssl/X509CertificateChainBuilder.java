/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/X509CertificateChainBuilder.java $
 * $Revision: 134 $
 * $Date: 2008-02-26 21:30:48 -0800 (Tue, 26 Feb 2008) $
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

import java.io.FileInputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedList;

/**
 * Utility for building X509 certificate chains.
 *
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 16-Nov-2005
 */
public class X509CertificateChainBuilder {
    /**
     * Builds the ordered certificate chain upwards from the startingPoint.
     * Uses the supplied X509Certificate[] array to search for the parent,
     * grandparent, and higher ancestor certificates.  Stops at self-signed
     * certificates, or when no ancestor can be found.
     * <p/>
     * Thanks to Joe Whitney for helping me put together a Big-O( m * n )
     * implementation where m = the length of the final certificate chain.
     * For a while I was using a Big-O( n ^ 2 ) implementation!
     *
     * @param startingPoint the X509Certificate for which we want to find
     *                      ancestors
     * @param certificates  A pool of certificates in which we expect to find
     *                      the startingPoint's ancestors.
     * @return Array of X509Certificates, starting with the "startingPoint" and
     *         ending with highest level ancestor we could find in the supplied
     *         collection.
     * @throws java.security.NoSuchAlgorithmException
     *          on unsupported signature
     *          algorithms.
     * @throws java.security.InvalidKeyException
     *          on incorrect key.
     * @throws java.security.NoSuchProviderException
     *          if there's no default provider.
     * @throws java.security.cert.CertificateException
     *          on encoding errors.
     */
    public static X509Certificate[] buildPath(X509Certificate startingPoint,
                                              Certificate[] certificates)
        throws NoSuchAlgorithmException, InvalidKeyException,
        NoSuchProviderException, CertificateException {
        // Use a LinkedList, because we do lots of random it.remove() operations.
        return buildPath(startingPoint,
            new LinkedList(Arrays.asList(certificates)));
    }

    /**
     * Builds the ordered certificate chain upwards from the startingPoint.
     * Uses the supplied collection to search for the parent, grandparent,
     * and higher ancestor certificates.  Stops at self-signed certificates,
     * or when no ancestor can be found.
     * <p/>
     * Thanks to Joe Whitney for helping me put together a Big-O( m * n )
     * implementation where m = the length of the final certificate chain.
     * For a while I was using a Big-O( n ^ 2 ) implementation!
     *
     * @param startingPoint the X509Certificate for which we want to find
     *                      ancestors
     * @param certificates  A pool of certificates in which we expect to find
     *                      the startingPoint's ancestors.
     * @return Array of X509Certificates, starting with the "startingPoint" and
     *         ending with highest level ancestor we could find in the supplied
     *         collection.
     * @throws java.security.NoSuchAlgorithmException
     *          on unsupported signature
     *          algorithms.
     * @throws java.security.InvalidKeyException
     *          on incorrect key.
     * @throws java.security.NoSuchProviderException
     *          if there's no default provider.
     * @throws java.security.cert.CertificateException
     *          on encoding errors.
     */
    public static X509Certificate[] buildPath(X509Certificate startingPoint,
                                              Collection certificates)
        throws NoSuchAlgorithmException, InvalidKeyException,
        NoSuchProviderException, CertificateException {
        LinkedList path = new LinkedList();
        path.add(startingPoint);
        boolean nodeAdded = true;
        // Keep looping until an iteration happens where we don't add any nodes
        // to our path.
        while (nodeAdded) {
            // We'll start out by assuming nothing gets added.  If something
            // gets added, then nodeAdded will be changed to "true".
            nodeAdded = false;
            X509Certificate top = (X509Certificate) path.getLast();
            if (isSelfSigned(top)) {
                // We're self-signed, so we're done!
                break;
            }

            // Not self-signed.  Let's see if we're signed by anyone in the
            // collection.
            Iterator it = certificates.iterator();
            while (it.hasNext()) {
                X509Certificate x509 = (X509Certificate) it.next();
                if (verify(top, x509.getPublicKey())) {
                    // We're signed by this guy!  Add him to the chain we're
                    // building up.
                    path.add(x509);
                    nodeAdded = true;
                    it.remove(); // Not interested in this guy anymore!
                    break;
                }
                // Not signed by this guy, let's try the next guy.
            }
        }
        X509Certificate[] results = new X509Certificate[path.size()];
        path.toArray(results);
        return results;
    }

    public static boolean isSelfSigned(X509Certificate cert)
        throws CertificateException, InvalidKeyException,
        NoSuchAlgorithmException, NoSuchProviderException {

        return verify(cert, cert.getPublicKey());
    }

    public static boolean verify(X509Certificate cert, PublicKey key)
        throws CertificateException, InvalidKeyException,
        NoSuchAlgorithmException, NoSuchProviderException {

        String sigAlg = cert.getSigAlgName();
        String keyAlg = key.getAlgorithm();
        sigAlg = sigAlg != null ? sigAlg.trim().toUpperCase() : "";
        keyAlg = keyAlg != null ? keyAlg.trim().toUpperCase() : "";
        if (keyAlg.length() >= 2 && sigAlg.endsWith(keyAlg)) {
            try {
                cert.verify(key);
                return true;
            } catch (SignatureException se) {
                return false;
            }
        } else {
            return false;
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("Usage: [special-one] [file-with-certs]");
            System.exit(1);
        }
        FileInputStream f1 = new FileInputStream(args[0]);
        FileInputStream f2 = new FileInputStream(args[1]);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate theOne = (X509Certificate) cf.generateCertificate(f1);
        Collection c = cf.generateCertificates(f2);

        X509Certificate[] path = buildPath(theOne, c);
        for (int i = 0; i < path.length; i++) {
            System.out.println(Certificates.getCN(path[i]));
        }
    }
}
