package org.apache.commons.ssl;

import static org.apache.commons.ssl.JUnitConfig.TEST_HOME;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.*;
import org.junit.Test;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import javax.net.ssl.SSLSocket;

public class TestKeyMaterial {
    public static final char[] PASSWORD1 = "changeit".toCharArray();
    public static final char[] PASSWORD2 = "itchange".toCharArray();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testKeystores() throws Exception {
        String samplesDir = TEST_HOME + "samples/keystores";
        File dir = new File(samplesDir);
        String[] files = dir.list();
        Arrays.sort(files, String.CASE_INSENSITIVE_ORDER);
        for (String f : files) {
            String F = f.toUpperCase(Locale.ENGLISH);
            if (F.endsWith(".KS") || F.contains("PKCS12")) {
                examineKeyStore(samplesDir, f, null);
            } else if (F.endsWith(".PEM")) {
                examineKeyStore(samplesDir, f, "rsa.key");
            }
        }
    }

    private static void examineKeyStore(String dir, String fileName, String file2) throws Exception {
        String FILENAME = fileName.toUpperCase(Locale.ENGLISH);
        boolean hasMultiPassword = FILENAME.contains(".2PASS.");

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

        SSLServer server = new SSLServer();
        server.setKeyMaterial(km);
        ServerSocket ss = server.createServerSocket(0);
        int port = ss.getLocalPort();
        startServerThread(ss);
        Thread.sleep(1);


        SSLClient client = new SSLClient();
        client.setTrustMaterial(TrustMaterial.TRUST_ALL);
        client.setCheckHostname(false);
        SSLSocket s = (SSLSocket) client.createSocket("localhost", port);
        s.getSession().getPeerCertificates();
        InputStream in = s.getInputStream();
        Util.streamToBytes(in);
        in.close();
        // System.out.println(Certificates.toString((X509Certificate) certs[0]));
        s.close();

        System.out.println("\t SUCCESS! ");
    }


    private static void startServerThread(final ServerSocket ss) {
        Runnable r = new Runnable() {
            public void run() {
                try {
                    Socket s = ss.accept();
                    OutputStream out = s.getOutputStream();
                    Thread.sleep(1);
                    out.write("Hello From Server\n".getBytes());
                    Thread.sleep(1);
                    out.close();
                    s.close();
                } catch (Exception e) {

                    System.out.println("Test ssl server exception: " + e);

                }
            }
        };

        new Thread(r).start();
    }

}
