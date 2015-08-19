package org.apache.commons.ssl;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.TreeSet;

/**
 * @author Julius Davies
 * @since 4-Jul-2007
 */
public class PBETestCreate {

    public static void main(String[] args) throws Exception {
        FileInputStream in = new FileInputStream(args[0]);
        Properties p = new Properties();
        p.load(in);
        in.close();

        String targetDir = p.getProperty("target");
        File dir = new File(targetDir);
        dir.mkdirs();
        if (!dir.exists()) {
            throw new IOException(dir.getCanonicalPath() + " doesn't exist!");
        }

        TreeSet ciphers = new TreeSet();
        Iterator it = p.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry entry = (Map.Entry) it.next();
            String key = (String) entry.getKey();
            if (!"target".equalsIgnoreCase(key)) {
                ciphers.add(key);
                ciphers.add(key + "-cbc");
                ciphers.add(key + "-cfb");
                ciphers.add(key + "-cfb1");
                ciphers.add(key + "-cfb8");
                ciphers.add(key + "-ecb");
                ciphers.add(key + "-ofb");
            }
        }

        byte[] toEncrypt = "Hello World!".getBytes("UTF-8");
        char[] pwd = "changeit".toCharArray();
        it = ciphers.iterator();
        while (it.hasNext()) {
            String cipher = (String) it.next();
            String cipherPadded = Util.pad(cipher, 15, false);
            String fileNameBase64 = cipher + ".base64";
            String fileNameRaw = cipher + ".raw";
            String d = dir.getCanonicalPath() + "/";
            try {
                byte[] base64 = OpenSSL.encrypt(cipher, pwd, toEncrypt, true);
                FileOutputStream out = new FileOutputStream(d + fileNameBase64);
                out.write(base64);
                out.close();
            }
            catch (Exception e) {
                System.err.println("FAILURE \t" + cipherPadded + "\t" + fileNameBase64 + "\t" + e);
            }

            try {
                byte[] raw = OpenSSL.encrypt(cipher, pwd, toEncrypt, false);
                FileOutputStream out = new FileOutputStream(d + fileNameRaw);
                out.write(raw);
                out.close();
            }
            catch (Exception e) {
                System.err.println("FAILURE \t" + cipherPadded + "\t" + fileNameRaw + "\t" + e);
            }

        }
    }

}
