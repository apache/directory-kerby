/*
 * ====================================================================
 *
 *  Copyright 1999-2006 The Apache Software Foundation
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
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * <p/>
 * TrustSSLProtocolSocketFactory allows you exercise full control over the
 * HTTPS server certificates you are going to trust.  Instead of relying
 * on the Certificate Authorities already present in "jre/lib/security/cacerts",
 * TrustSSLProtocolSocketFactory only trusts the public certificates you provide
 * to its constructor.
 * </p>
 * <p/>
 * TrustSSLProtocolSocketFactory can be used to create SSL {@link java.net.Socket}s
 * that accepts self-signed certificates.  Unlike EasySSLProtocolSocketFactory,
 * TrustSSLProtocolSocketFactory can be used in production.  This is because
 * it forces you to pre-install the self-signed certificate you are going to
 * trust locally.
 * <p/>
 * TrustSSLProtocolSocketFactory can parse both Java Keystore Files (*.jks)
 * and base64 PEM encoded public certificates (*.pem).
 * </p>
 * <p/>
 * Example of using TrustSSLProtocolSocketFactory
 * <pre>
 * 1.  First we must find the certificate we want to trust.  In this example
 *     we'll use gmail.google.com's certificate.
 * <p/>
 *   openssl s_client -showcerts -connect gmail.google.com:443
 * <p/>
 * 2.  Cut & paste into a "cert.pem" any certificates you are interested in
 *     trusting in accordance with your security policies.  In this example I'll
 *     actually use the current "gmail.google.com" certificate (instead of the
 *     Thawte CA certificate that signed the gmail certificate - that would be
 *     too boring) - but it expires on June 7th, 2006, so this example won't be
 *     useful for very long!
 * <p/>
 * Here's what my "cert.pem" file looks like:
 * <p/>
 * -----BEGIN CERTIFICATE-----
 * MIIDFjCCAn+gAwIBAgIDP3PeMA0GCSqGSIb3DQEBBAUAMEwxCzAJBgNVBAYTAlpB
 * MSUwIwYDVQQKExxUaGF3dGUgQ29uc3VsdGluZyAoUHR5KSBMdGQuMRYwFAYDVQQD
 * Ew1UaGF3dGUgU0dDIENBMB4XDTA1MDYwNzIyMTI1N1oXDTA2MDYwNzIyMTI1N1ow
 * ajELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDU1v
 * dW50YWluIFZpZXcxEzARBgNVBAoTCkdvb2dsZSBJbmMxGTAXBgNVBAMTEGdtYWls
 * Lmdvb2dsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALoRiWYW0hZw
 * 9TSn3s9912syZg1CP2TaC86PU1Ao2qf3pVu7Mx10Wl8W+aKZrQlvrYjTwku4sEh+
 * 9uI+gWnfmCd0OyVcXr1eFOGCYiiyaPv79Wtb0m0d8GuiRSJhYkZGzGlgFViws2vR
 * BAMCD2fdp7WGJUVGYOO+s52dgAMUHQXxAgMBAAGjgecwgeQwKAYDVR0lBCEwHwYI
 * KwYBBQUHAwEGCCsGAQUFBwMCBglghkgBhvhCBAEwNgYDVR0fBC8wLTAroCmgJ4Yl
 * aHR0cDovL2NybC50aGF3dGUuY29tL1RoYXd0ZVNHQ0NBLmNybDByBggrBgEFBQcB
 * AQRmMGQwIgYIKwYBBQUHMAGGFmh0dHA6Ly9vY3NwLnRoYXd0ZS5jb20wPgYIKwYB
 * BQUHMAKGMmh0dHA6Ly93d3cudGhhd3RlLmNvbS9yZXBvc2l0b3J5L1RoYXd0ZV9T
 * R0NfQ0EuY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQEEBQADgYEAktM1l1cV
 * ebi+Uo6fCE/eLnvvY6QbNNCsU5Pi9B5E1BlEUG+AGpgzE2cSPw1N4ZZb+2AWWwjx
 * H8/IrJ143KZZXM49ri3Z2e491Jj8qitrMauT7/hb16Jw6I02/74/do4TtHu/Eifr
 * EZCaSOobSHGeufHjlqlC3ehC4Bx4mLexIMk=
 * -----END CERTIFICATE-----
 * <p/>
 * 3.  Run "openssl x509" to analyze the certificate more deeply.  This helps
 *     us answer questions like "Do we really want to trust it?  When does it
 *     expire? What's the value of the CN (Common Name) field?".
 * <p/>
 *     "openssl x509" is also super cool, and will impress all your friends,
 *     coworkers, family, and that cute girl at the starbucks.   :-)
 * <p/>
 *     If you dig through "man x509" you'll find this example.  Run it:
 * <p/>
 *    openssl x509 -in cert.pem -noout -text
 * <p/>
 * 4.  Rename "cert.pem" to "gmail.pem" so that step 5 works.
 * <p/>
 * 5.  Setup the TrustSSLProtocolSocketFactory to trust "gmail.google.com"
 *     for URLS of the form "https-gmail://" - but don't trust anything else
 *     when using "https-gmail://":
 * <p/>
 *     TrustSSLProtocolSocketFactory sf = new TrustSSLProtocolSocketFactory( "/path/to/gmail.pem" );
 *     Protocol trustHttps = new Protocol("https-gmail", sf, 443);
 *     Protocol.registerProtocol("https-gmail", trustHttps);
 * <p/>
 *     HttpClient client = new HttpClient();
 *     GetMethod httpget = new GetMethod("https-gmail://gmail.google.com/");
 *     client.executeMethod(httpget);
 * <p/>
 * 6.  Notice that "https-gmail://" cannot connect to "www.wellsfargo.com" -
 *     the server's certificate isn't trusted!  It would still work using
 *     regular "https://" because Java would use the "jre/lib/security/cacerts"
 *     file.
 * <p/>
 *     httpget = new GetMethod("https-gmail://www.wellsfargo.com/");
 *     client.executeMethod(httpget);
 * <p/>
 * javax.net.ssl.SSLHandshakeException: sun.security.validator.ValidatorException: No trusted certificate found
 * <p/>
 * <p/>
 * 7.  Of course "https-gmail://" cannot connect to hosts where the CN field
 *     in the certificate doesn't match the hostname.  The same is supposed to
 *     be true of regular "https://", but HTTPClient is a bit lenient.
 * <p/>
 *     httpget = new GetMethod("https-gmail://gmail.com/");
 *     client.executeMethod(httpget);
 * <p/>
 * javax.net.ssl.SSLException: hostname in certificate didn't match: &lt;gmail.com> != &lt;gmail.google.com>
 * <p/>
 * <p/>
 * 8.  You can use "*.jks" files instead of "*.pem" if you prefer.  Use the 2nd constructor
 *     in that case to pass along the JKS password:
 * <p/>
 *   new TrustSSLProtocolSocketFactory( "/path/to/gmail.jks", "my_password".toCharArray() );
 * <p/>
 * </pre>
 *
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 *         <p/>
 *         <p/>
 *         DISCLAIMER: HttpClient developers DO NOT actively support this component.
 *         The component is provided as a reference material, which may be inappropriate
 *         for use without additional customization.
 *         </p>
 * @since 17-Feb-2006
 */

public class TrustSSLProtocolSocketFactory extends HttpSecureProtocol {

    /**
     * @param pathToTrustStore Path to either a ".jks" Java Key Store, or a
     *                         ".pem" base64 encoded certificate.  If it's a
     *                         ".pem" base64 certificate, the file must start
     *                         with "------BEGIN CERTIFICATE-----", and must end
     *                         with "-------END CERTIFICATE--------".
     */
    public TrustSSLProtocolSocketFactory(String pathToTrustStore)
        throws GeneralSecurityException, IOException {
        this(pathToTrustStore, null);
    }

    /**
     * @param pathToTrustStore Path to either a ".jks" Java Key Store, or a
     *                         ".pem" base64 encoded certificate.  If it's a
     *                         ".pem" base64 certificate, the file must start
     *                         with "------BEGIN CERTIFICATE-----", and must end
     *                         with "-------END CERTIFICATE--------".
     * @param password         Password to open the ".jks" file.  If "truststore"
     *                         is a ".pem" file, then password can be null; if
     *                         password isn't null and we're using a ".pem" file,
     *                         then technically, this becomes the password to
     *                         open up the special in-memory keystore we create
     *                         to hold the ".pem" file, but it's not important at
     *                         all.
     * @throws java.security.cert.CertificateException
     * @throws java.security.KeyStoreException
     * @throws java.io.IOException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.KeyManagementException
     */
    public TrustSSLProtocolSocketFactory(String pathToTrustStore, char[] password)
        throws GeneralSecurityException, IOException {
        super();
        TrustMaterial tm;
        try {
            tm = new KeyMaterial(pathToTrustStore, password);
        } catch (KeyStoreException kse) {
            // KeyMaterial constructor blows up in no keys found,
            // so we fall back to TrustMaterial constructor instead.
            tm = new TrustMaterial(pathToTrustStore, password);
        }
        super.setTrustMaterial(tm);
    }

}
