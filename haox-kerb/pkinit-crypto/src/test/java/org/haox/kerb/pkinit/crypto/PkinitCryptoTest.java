package org.haox.kerb.pkinit.crypto;

import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.List;

/**
 openssl genrsa -out cakey.pem 2048
 openssl req -key cakey.pem -new -x509 -out cacert.pem -days 3650
 vi extensions.kdc
 openssl genrsa -out kdckey.pem 2048
 openssl req -new -out kdc.req -key kdckey.pem
 env REALM=SH.INTEL.COM openssl x509 -req -in kdc.req -CAkey cakey.pem \
 -CA cacert.pem -out kdc.pem -days 365 -extfile extensions.kdc -extensions kdc_cert -CAcreateserial
 */
public class PkinitCryptoTest {

    @Test
    public void loadCert() throws CertificateException, IOException {
        InputStream res = getClass().getResourceAsStream("/usercert.pem");
        List<Certificate> certs = PkinitCrypto.getCerts(res);
        Certificate userCert = certs.iterator().next();

        Assert.assertNotNull(userCert);
    }
}