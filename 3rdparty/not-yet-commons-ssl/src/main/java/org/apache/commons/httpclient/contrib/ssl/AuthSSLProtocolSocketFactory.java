/*
 * $Header$
 * $Revision: 168 $
 * $Date: 2014-05-06 16:25:46 -0700 (Tue, 06 May 2014) $
 *
 * ====================================================================
 *
 *  Copyright 2002-2006 The Apache Software Foundation
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */

package org.apache.commons.httpclient.contrib.ssl;

import org.apache.commons.ssl.HttpSecureProtocol;
import org.apache.commons.ssl.KeyMaterial;
import org.apache.commons.ssl.TrustMaterial;

import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;

/**
 * <p/>
 * AuthSSLProtocolSocketFactory can be used to validate the identity of the HTTPS
 * server against a list of trusted certificates and to authenticate to the HTTPS
 * server using a private key.
 * </p>
 * <p/>
 * <p/>
 * AuthSSLProtocolSocketFactory will enable server authentication when supplied with
 * a {@link java.security.KeyStore truststore} file containg one or several trusted certificates.
 * The client secure socket will reject the connection during the SSL session handshake
 * if the target HTTPS server attempts to authenticate itself with a non-trusted
 * certificate.
 * </p>
 * <p/>
 * <p/>
 * Use JDK keytool utility to import a trusted certificate and generate a truststore file:
 * <pre>
 *     keytool -import -alias "my server cert" -file server.crt -keystore my.truststore
 *    </pre>
 * </p>
 * <p/>
 * <p/>
 * AuthSSLProtocolSocketFactory will enable client authentication when supplied with
 * a {@link java.security.KeyStore keystore} file containg a private key/public certificate pair.
 * The client secure socket will use the private key to authenticate itself to the target
 * HTTPS server during the SSL session handshake if requested to do so by the server.
 * The target HTTPS server will in its turn verify the certificate presented by the client
 * in order to establish client's authenticity
 * </p>
 * <p/>
 * <p/>
 * Use the following sequence of actions to generate a keystore file
 * </p>
 * <ul>
 * <li>
 * <p/>
 * Use JDK keytool utility to generate a new key
 * <pre>keytool -genkey -v -alias "my client key" -validity 365 -keystore my.keystore</pre>
 * For simplicity use the same password for the key as that of the keystore
 * </p>
 * </li>
 * <li>
 * <p/>
 * Issue a certificate signing request (CSR)
 * <pre>keytool -certreq -alias "my client key" -file mycertreq.csr -keystore my.keystore</pre>
 * </p>
 * </li>
 * <li>
 * <p/>
 * Send the certificate request to the trusted Certificate Authority for signature.
 * One may choose to act as her own CA and sign the certificate request using a PKI
 * tool, such as OpenSSL.
 * </p>
 * </li>
 * <li>
 * <p/>
 * Import the trusted CA root certificate
 * <pre>keytool -import -alias "my trusted ca" -file caroot.crt -keystore my.keystore</pre>
 * </p>
 * </li>
 * <li>
 * <p/>
 * Import the PKCS#7 file containg the complete certificate chain
 * <pre>keytool -import -alias "my client key" -file mycert.p7 -keystore my.keystore</pre>
 * </p>
 * </li>
 * <li>
 * <p/>
 * Verify the content the resultant keystore file
 * <pre>keytool -list -v -keystore my.keystore</pre>
 * </p>
 * </li>
 * </ul>
 * <p/>
 * Example of using custom protocol socket factory for a specific host:
 * <pre>
 *     Protocol authhttps = new Protocol("https",
 *          new AuthSSLProtocolSocketFactory(
 *              new URL("file:my.keystore"), "mypassword",
 *              new URL("file:my.truststore"), "mypassword"), 443);
 * <p/>
 *     HttpClient client = new HttpClient();
 *     client.getHostConfiguration().setHost("localhost", 443, authhttps);
 *     // use relative url only
 *     GetMethod httpget = new GetMethod("/");
 *     client.executeMethod(httpget);
 *     </pre>
 * </p>
 * <p/>
 * Example of using custom protocol socket factory per default instead of the standard one:
 * <pre>
 *     Protocol authhttps = new Protocol("https",
 *          new AuthSSLProtocolSocketFactory(
 *              new URL("file:my.keystore"), "mypassword",
 *              new URL("file:my.truststore"), "mypassword"), 443);
 *     Protocol.registerProtocol("https", authhttps);
 * <p/>
 *     HttpClient client = new HttpClient();
 *     GetMethod httpget = new GetMethod("https://localhost/");
 *     client.executeMethod(httpget);
 *     </pre>
 * </p>
 *
 * @author <a href="mailto:oleg -at- ural.ru">Oleg Kalnichevski</a>
 *         <p/>
 *         <p/>
 *         DISCLAIMER: HttpClient developers DO NOT actively support this component.
 *         The component is provided as a reference material, which may be inappropriate
 *         for use without additional customization.
 *         </p>
 */

public class AuthSSLProtocolSocketFactory extends HttpSecureProtocol {

    /**
     * Constructor for AuthSSLProtocolSocketFactory. Either a keystore or truststore file
     * must be given. Otherwise SSL context initialization error will result.
     *
     * @param keystoreUrl        URL of the keystore file. May be <tt>null</tt> if HTTPS client
     *                           authentication is not to be used.
     * @param keystorePassword   Password to unlock the keystore. IMPORTANT: this implementation
     *                           assumes that the same password is used to protect the key and the keystore itself.
     * @param truststoreUrl      URL of the truststore file. May be <tt>null</tt> if HTTPS server
     *                           authentication is not to be used.
     * @param truststorePassword Password to unlock the truststore.
     */
    public AuthSSLProtocolSocketFactory(final URL keystoreUrl,
                                        final String keystorePassword,
                                        final URL truststoreUrl,
                                        final String truststorePassword)
        throws GeneralSecurityException, IOException {

        super();

        // prepare key material
        if (keystoreUrl != null) {
            char[] ksPass = null;
            if (keystorePassword != null) {
                ksPass = keystorePassword.toCharArray();
            }
            KeyMaterial km = new KeyMaterial(keystoreUrl, ksPass);
            super.setKeyMaterial(km);
        }

        // prepare trust material
        if (truststoreUrl != null) {
            char[] tsPass = null;
            if (truststorePassword != null) {
                tsPass = truststorePassword.toCharArray();
            }
            TrustMaterial tm;
            try {
                tm = new KeyMaterial(truststoreUrl, tsPass);
            } catch (KeyStoreException kse) {
                // KeyMaterial constructor blows up in no keys found,
                // so we fall back to TrustMaterial constructor instead.
                tm = new TrustMaterial(truststoreUrl, tsPass);
            }
            super.setTrustMaterial(tm);
        }
    }

}
