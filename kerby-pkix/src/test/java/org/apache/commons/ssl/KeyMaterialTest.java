package org.apache.commons.ssl;

import org.apache.kerby.util.EncryptoUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import java.io.File;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import static org.apache.commons.ssl.JUnitConfig.TEST_HOME;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

public class KeyMaterialTest {
    public static final char[] PASSWORD1 = "changeit".toCharArray();
    public static final char[] PASSWORD2 = "itchange".toCharArray();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testKeystores() throws Exception {
        String samplesDir = TEST_HOME + "keystores";
        File dir = new File(samplesDir);
        String[] files = dir.list();
        Arrays.sort(files, String.CASE_INSENSITIVE_ORDER);
        for (String f : files) {
            String file = f.toUpperCase(Locale.ENGLISH);
            if (file.endsWith(".KS") || file.contains("PKCS12")) {
                examineKeyStore(samplesDir, f, null);
            } else if (file.endsWith(".PEM")) {
                examineKeyStore(samplesDir, f, "rsa.key");
            }
        }
    }

    private static void examineKeyStore(String dir, String fileName, String file2) throws Exception {
        String filename = fileName.toUpperCase(Locale.ENGLISH);
        boolean hasMultiPassword = filename.contains(".2PASS.");

        System.out.print("Testing KeyMaterial: " + dir + "/" + fileName);        
        char[] pass1 = PASSWORD1;
        char[] pass2 = PASSWORD1;
        if (hasMultiPassword) {
            pass2 = PASSWORD2;
        }

        file2 = file2 != null ? dir + "/" + file2 : null;

        Date today = new Date();
        KeyMaterial km;


        try {
            assumeTrue(EncryptoUtil.isAES256Enabled());
            km = new KeyMaterial(dir + "/" + fileName, file2, pass1, pass2);
        } catch (ProbablyBadPasswordException pbpe) {
            System.out.println("  WARN:  " + pbpe);
            return;
        }
        assertEquals("keymaterial-contains-1-alias", 1, km.getAliases().size());
        for (X509Certificate[] cert : (List<X509Certificate[]>) km.getAssociatedCertificateChains()) {
            for (X509Certificate c : cert) {
                assertTrue("certchain-valid-dates", c.getNotAfter().after(today));
            }
        }

        System.out.println("\t SUCCESS! ");
    }
}
