package org.apache.commons.ssl;

import static org.apache.commons.ssl.JUnitConfig.TEST_HOME;
import static org.junit.Assert.*;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

public class TestOpenSSL {

    public void encTest(String cipher) throws Exception {
        Random random = new Random();
        char[] pwd = {'!', 'E', 'i', 'k', 'o', '?'};

        for (int i = 0; i < 4567; i++) {
            byte[] buf = new byte[i];
            random.nextBytes(buf);
            byte[] enc = OpenSSL.encrypt(cipher, pwd, buf);
            byte[] dec = OpenSSL.decrypt(cipher, pwd, enc);
            boolean result = Arrays.equals(buf, dec);
            if (!result) {
                System.out.println();
                System.out.println("Failed on : " + i);
            }
            assertTrue(result);
        }

        for (int i = 5; i < 50; i++) {
            int testSize = (i * 1000) + 123;
            byte[] buf = new byte[testSize];
            random.nextBytes(buf);
            byte[] enc = OpenSSL.encrypt(cipher, pwd, buf);
            byte[] dec = OpenSSL.decrypt(cipher, pwd, enc);
            boolean result = Arrays.equals(buf, dec);
            if (!result) {
                System.out.println();
                System.out.println("Failed on : " + testSize);
            }
            assertTrue(result);
        }

    }

    @Test
    public void testDES3Bytes() throws Exception {
        encTest("des3");
    }

    @Test
    public void testAES128Bytes() throws Exception {
        encTest("aes128");
    }

    @Test
    public void testRC2Bytes() throws Exception {
        encTest("rc2");
    }

    @Test
    public void testDESBytes() throws Exception {
        encTest("des");
    }

    @Test
    public void testDecryptPBE() throws Exception {
        File d = new File(TEST_HOME + "samples/pbe");
        File[] files = d.listFiles();
        if (files == null) {
            fail("No testDecryptPBE() files to test!");
        }
        int testCount = 0;
        Arrays.sort(files);
        for (File f : files) {
            testCount += process(f, 0);
        }
        System.out.println(testCount + " pbe test files successfully decrypted.");
    }

    private static int process(File f, int depth) throws Exception {
        int sum = 0;
        String name = f.getName();
        if ("CVS".equalsIgnoreCase(name)) {
            return 0;
        }
        if (".svn".equalsIgnoreCase(name)) {
            return 0;
        }
        if (name.toUpperCase().startsWith("README")) {
            return 0;
        }

        if (f.isDirectory()) {
            if (depth <= 7) {
                File[] files = f.listFiles();
                if (files == null) {
                    return 0;
                }
                Arrays.sort(files);
                for (File ff : files) {
                    sum += process(ff, depth + 1);
                }
            } else {
                System.out.println("IGNORING [" + f + "].  Directory too deep (" + depth + ").");
            }
        } else {
            if (f.isFile() && f.canRead()) {
                String fileName = f.getName();
                int x = fileName.indexOf('.');
                if (x < 0) {
                    return 0;
                }
                String cipher = fileName.substring(0, x);
                String cipherPadded = Util.pad(cipher, 20, false);
                String filePadded = Util.pad(fileName, 25, false);
                FileInputStream in = null;
                try {
                    in = new FileInputStream(f);
                    byte[] encrypted = Util.streamToBytes(in);
                    char[] pwd = "changeit".toCharArray();
                    try {
                        byte[] result = OpenSSL.decrypt(cipher, pwd, encrypted);
                        String s = new String(result, "ISO-8859-1");
                        assertTrue(cipherPadded + "." + filePadded + " decrypts to 'Hello World!'", "Hello World!".equals(s));
                        return 1;
                    } catch (NoSuchAlgorithmException nsae) {
                        System.out.println("Warn: " + cipherPadded + filePadded + " NoSuchAlgorithmException");
                        return 0;
                    } catch (ArithmeticException ae) {
                        if (cipherPadded.contains("cfb1")) {
                            System.out.println("Warn: " + cipherPadded + filePadded + " BouncyCastle can't handle cfb1 " + ae);
                            return 0;
                        } else {
                            throw ae;
                        }
                    }
                } finally {
                    if (in != null) {
                        in.close();
                    }
                }
            }
        }
        return sum;
    }

}
