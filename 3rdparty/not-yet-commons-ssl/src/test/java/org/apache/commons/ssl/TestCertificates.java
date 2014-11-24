package org.apache.commons.ssl;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import javax.security.auth.x500.X500Principal;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.apache.commons.ssl.JUnitConfig.TEST_HOME;
import static org.mockito.Mockito.when;

/**
 * Created by julius on 06/09/14.
 */
@RunWith(MockitoJUnitRunner.class)
public class TestCertificates {

    @Mock
    private X509Certificate x509;

    @Test
    public void testGetCNsMocked() {
        X500Principal normal = new X500Principal("CN=abc,OU=ou,O=o,C=canada,EMAILADDRESS=bob@bob.com");
        X500Principal bad1 = new X500Principal("CN=\"abc,CN=foo.com,\",OU=ou,O=o,C=canada,EMAILADDRESS=bob@bob.com");
        X500Principal bad2 = new X500Principal("ou=\",CN=evil.ca,\",  CN=good.net");

        when(x509.getSubjectX500Principal()).thenReturn(normal);
        String[] cns = Certificates.getCNs(x509);
        Assert.assertEquals(1, cns.length);
        Assert.assertEquals("abc", cns[0]);

        when(x509.getSubjectX500Principal()).thenReturn(bad2);
        cns = Certificates.getCNs(x509);
        Assert.assertEquals(1, cns.length);
        Assert.assertEquals("good.net", cns[0]);

        when(x509.getSubjectX500Principal()).thenReturn(bad1);
        cns = Certificates.getCNs(x509);
        Assert.assertEquals(1, cns.length);
        Assert.assertEquals("abc,CN=foo.com,", cns[0]);
    }

    @Test
    public void testGetCNsReal() throws IOException, GeneralSecurityException {
        String samplesDir = TEST_HOME + "samples/x509";

        TrustMaterial tm = new TrustMaterial(samplesDir + "/x509_three_cns_foo_bar_hanako.pem");
        X509Certificate c = (X509Certificate) tm.getCertificates().first();
        String[] cns = Certificates.getCNs(c);
        Assert.assertEquals(3, cns.length);
        Assert.assertEquals("foo.com", cns[0]);
        Assert.assertEquals("bar.com", cns[1]);
        Assert.assertEquals("花子.co.jp", cns[2]);

        tm = new TrustMaterial(samplesDir + "/x509_foo_bar_hanako.pem");
        c = (X509Certificate) tm.getCertificates().first();
        cns = Certificates.getCNs(c);
        Assert.assertEquals(1, cns.length);
        Assert.assertEquals("foo.com", cns[0]);

        tm = new TrustMaterial(samplesDir + "/x509_wild_co_jp.pem");
        c = (X509Certificate) tm.getCertificates().first();
        cns = Certificates.getCNs(c);
        Assert.assertEquals(1, cns.length);
        Assert.assertEquals("*.co.jp", cns[0]);

        tm = new TrustMaterial(samplesDir + "/x509_wild_foo_bar_hanako.pem");
        c = (X509Certificate) tm.getCertificates().first();
        cns = Certificates.getCNs(c);
        Assert.assertEquals(1, cns.length);
        Assert.assertEquals("*.foo.com", cns[0]);

        tm = new TrustMaterial(samplesDir + "/x509_wild_foo.pem");
        c = (X509Certificate) tm.getCertificates().first();
        cns = Certificates.getCNs(c);
        Assert.assertEquals(1, cns.length);
        Assert.assertEquals("*.foo.com", cns[0]);
    }
}