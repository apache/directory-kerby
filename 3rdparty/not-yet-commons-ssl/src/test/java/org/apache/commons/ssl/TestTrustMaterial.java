package org.apache.commons.ssl;

import static org.apache.commons.ssl.JUnitConfig.TEST_HOME;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;

public class TestTrustMaterial {

    File pemFile = new File(TEST_HOME + "samples/x509/certificate.pem");
    File derFile = new File(TEST_HOME + "samples/x509/certificate.der");

    @Test
    public void theTest() throws GeneralSecurityException, IOException {
        // TrustMaterial in 0.3.13 couldn't load cacerts if it contained any private keys.
        TrustMaterial tm = new TrustMaterial(TEST_HOME + "samples/cacerts-with-78-entries-and-one-private-key.jks");
        Assert.assertEquals(78, tm.getCertificates().size());
    }

    @Test
    public void testLoadByFile() throws GeneralSecurityException, IOException {
        TrustMaterial tm1 = new TrustMaterial(pemFile);
        TrustMaterial tm2 = new TrustMaterial(derFile);
        Assert.assertTrue(equalKeystores(tm1, tm2));
    }

    @Test
    public void testLoadByBytes() throws GeneralSecurityException, IOException {
        TrustMaterial tm1 = new TrustMaterial(Util.fileToBytes(pemFile));
        TrustMaterial tm2 = new TrustMaterial(Util.fileToBytes(derFile));
        Assert.assertTrue(equalKeystores(tm1, tm2));

    }

    @Test
    public void testLoadByURL() throws GeneralSecurityException, IOException {
        TrustMaterial tm1 = new TrustMaterial(pemFile.toURI().toURL());
        TrustMaterial tm2 = new TrustMaterial(derFile.toURI().toURL());
        Assert.assertTrue(equalKeystores(tm1, tm2));
    }

    @Test
    public void testLoadByStream() throws GeneralSecurityException, IOException {
        TrustMaterial tm1 = new TrustMaterial(new FileInputStream(pemFile));
        TrustMaterial tm2 = new TrustMaterial(new FileInputStream(derFile));
        Assert.assertTrue(equalKeystores(tm1, tm2));

    }

    @Test
    public void testLoadByPath() throws GeneralSecurityException, IOException {
        TrustMaterial tm1 = new TrustMaterial(pemFile.getPath());
        TrustMaterial tm2 = new TrustMaterial(derFile.getPath());
        Assert.assertTrue(equalKeystores(tm1, tm2));
    }

    private static boolean equalKeystores(TrustMaterial tm1, TrustMaterial tm2) throws KeyStoreException {
        return Util.equals(tm1.getKeyStore(), tm2.getKeyStore());
    }
}
