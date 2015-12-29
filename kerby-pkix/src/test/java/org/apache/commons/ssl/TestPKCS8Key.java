package org.apache.commons.ssl;

import org.apache.kerby.util.EncryptoUtil;
import org.apache.kerby.util.Util;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.util.Arrays;
import java.util.Locale;

import static org.apache.commons.ssl.JUnitConfig.TEST_HOME;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

public class TestPKCS8Key {

    @Test
    public void testDSA() throws Exception {
        checkFiles("dsa");
    }

    @Test
    public void testRSA() throws Exception {
        checkFiles("rsa");
    }

    private static void checkFiles(String type) throws Exception {
        String password = "changeit";
        File dir = new File(TEST_HOME + type);
        File[] files = dir.listFiles();
        if (files == null) {
            fail("No files to test!");
            return;
        }
        byte[] original = null;
        for (File f : files) {
            String filename = f.getName();
            String fileName = filename.toUpperCase(Locale.ENGLISH);
            if (!fileName.endsWith(".PEM") && !fileName.endsWith(".DER")) {
                // not a sample file
                continue;
            }

            System.out.println("Checking PKCS file:" + filename);
            FileInputStream in = new FileInputStream(f);
            byte[] bytes = Util.streamToBytes(in);
            assumeTrue(EncryptoUtil.isAES256Enabled());
            PKCS8Key key = new PKCS8Key(bytes, password.toCharArray());
            byte[] decrypted = key.getDecryptedBytes();
            if (original == null) {
                original = decrypted;
            } else {
                boolean identical = Arrays.equals(original, decrypted);
                assertTrue(f.getCanonicalPath() + " - all " + type + " resources decrypt to same key", identical);
            }
        }

    }
}
