
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.ssl.HttpSecureProtocol;
import org.apache.commons.ssl.TrustMaterial;

import javax.net.ssl.SSLHandshakeException;
import java.net.URL;

/**
 *
 * Example of trusting certs to answer a question Sudip Shrestha posed on the
 * httpclient-user@jakarta.apache.org mailing list, Fri 5/5/2006.
 *
 * @author Julius Davies
 * @since May 5, 2006
 */
public class TrustExample {

/*
Microsoft IE trusts usertrust.com CA certs by default, but Java doesn't, so we need
to tell Java to.

Cert is good until 2019 !

openssl x509 -in cert.pem -noout -text
=======================================

Serial Number:
    44:be:0c:8b:50:00:24:b4:11:d3:36:2a:fe:65:0a:fd
Signature Algorithm: sha1WithRSAEncryption
Issuer: C=US, ST=UT, L=Salt Lake City, O=The USERTRUST Network, OU=http://www.usertrust.com, CN=UTN-USERFirst-Hardware
Validity
    Not Before: Jul  9 18:10:42 1999 GMT
    Not After : Jul  9 18:19:22 2019 GMT
Subject: C=US, ST=UT, L=Salt Lake City, O=The USERTRUST Network, OU=http://www.usertrust.com, CN=UTN-USERFirst-Hardware

X509v3 extensions:
    X509v3 Key Usage:
        Digital Signature, Non Repudiation, Certificate Sign, CRL Sign
    X509v3 Basic Constraints: critical
        CA:TRUE
    X509v3 Subject Key Identifier:
        A1:72:5F:26:1B:28:98:43:95:5D:07:37:D5:85:96:9D:4B:D2:C3:45
    X509v3 CRL Distribution Points:
        URI:http://crl.usertrust.com/UTN-USERFirst-Hardware.crl

    X509v3 Extended Key Usage:
        TLS Web Server Authentication, IPSec End System, IPSec Tunnel, IPSec User

*/
    private static byte[] pemCert = (
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIEdDCCA1ygAwIBAgIQRL4Mi1AAJLQR0zYq/mUK/TANBgkqhkiG9w0BAQUFADCB\n" +
            "lzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAlVUMRcwFQYDVQQHEw5TYWx0IExha2Ug\n" +
            "Q2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMSEwHwYDVQQLExho\n" +
            "dHRwOi8vd3d3LnVzZXJ0cnVzdC5jb20xHzAdBgNVBAMTFlVUTi1VU0VSRmlyc3Qt\n" +
            "SGFyZHdhcmUwHhcNOTkwNzA5MTgxMDQyWhcNMTkwNzA5MTgxOTIyWjCBlzELMAkG\n" +
            "A1UEBhMCVVMxCzAJBgNVBAgTAlVUMRcwFQYDVQQHEw5TYWx0IExha2UgQ2l0eTEe\n" +
            "MBwGA1UEChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMSEwHwYDVQQLExhodHRwOi8v\n" +
            "d3d3LnVzZXJ0cnVzdC5jb20xHzAdBgNVBAMTFlVUTi1VU0VSRmlyc3QtSGFyZHdh\n" +
            "cmUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCx98M4P7Sof885glFn\n" +
            "0G2f0v9Y8+efK+wNiVSZuTiZFvfgIXlIwrthdBKWHTxqctU8EGc6Oe0rE81m65UJ\n" +
            "M6Rsl7HoxuzBdXmcRl6Nq9Bq/bkqVRcQVLMZ8Jr28bFdtqdt++BxF2uiiPsA3/4a\n" +
            "MXcMmgF6sTLjKwEHOG7DpV4jvEWbe1DByTCP2+UretNb+zNAHqDVmBe8i4fDidNd\n" +
            "oI6yqqr2jmmIBsX6iSHzCJ1pLgkzmykNRg+MzEk0sGlRvfkGzWitZky8PqxhvQqI\n" +
            "DsjfPe58BEydCl5rkdbux+0ojatNh4lz0G6k0B4WixThdkQDf2Os5M1JnMWS9Ksy\n" +
            "oUhbAgMBAAGjgbkwgbYwCwYDVR0PBAQDAgHGMA8GA1UdEwEB/wQFMAMBAf8wHQYD\n" +
            "VR0OBBYEFKFyXyYbKJhDlV0HN9WFlp1L0sNFMEQGA1UdHwQ9MDswOaA3oDWGM2h0\n" +
            "dHA6Ly9jcmwudXNlcnRydXN0LmNvbS9VVE4tVVNFUkZpcnN0LUhhcmR3YXJlLmNy\n" +
            "bDAxBgNVHSUEKjAoBggrBgEFBQcDAQYIKwYBBQUHAwUGCCsGAQUFBwMGBggrBgEF\n" +
            "BQcDBzANBgkqhkiG9w0BAQUFAAOCAQEARxkP3nTGmZev/K0oXnWO6y1n7k57K9cM\n" +
            "//bey1WiCuFMVGWTYGufEpytXoMs61quwOQt9ABjHbjAbPLPSbtNk28Gpgoiskli\n" +
            "CE7/yMgUsogWXecB5BKV5UU0s4tpvc+0hY91UZ59Ojg6FEgSxvunOxqNDYJAB+gE\n" +
            "CJChicsZUN/KHAG8HQQZexB2lzvukJDKxA4fFm517zP4029bHpbj4HR3dHuKom4t\n" +
            "3XbWOTCC8KucUvIqx69JXn7HaOWCgchqJ/kniCrVWFCVH/A7HFe7fRQ5YiuayZSS\n" +
            "KqMiDP+JJn1fIytH1xUdqWqeUQ0qUZ6B+dQ7XnASfxAynB67nfhmqA==\n" +
            "-----END CERTIFICATE-----\n" ).getBytes();

    public static void main( String[] args ) throws Exception
    {
        HttpSecureProtocol f = new HttpSecureProtocol();

        // might as well trust the usual suspects:
        f.addTrustMaterial(TrustMaterial.CACERTS);

        // here's where we start trusting usertrust.com's CA:
        f.addTrustMaterial(new TrustMaterial( pemCert ));

        Protocol trustHttps = new Protocol("https", f, 443);
        Protocol.registerProtocol("https", trustHttps);

        HttpClient client = new HttpClient();
        GetMethod httpget = new GetMethod("https://www.usertrust.com/");
        client.executeMethod(httpget);
        String s = httpget.getStatusLine().toString();
        System.out.println( "HTTPClient: " + s );

        // Notice that Java still can't access it.  Only HTTPClient knows
        // to trust the cert!
        URL u = new URL( "https://www.usertrust.com/" );
        try
        {
            // This will throw an SSLHandshakeException
            u.openStream();
        }
        catch ( SSLHandshakeException she )
        {
            System.out.println( "Java:       " + she );
        }
    }

}
