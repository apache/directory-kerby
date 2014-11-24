package org.apache.commons.ssl;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.util.Properties;

public class JUnitConfig {

    public final static String TEST_HOME;

    static {
        String home = "";
        File f = new File(System.getProperty("user.home") + "/.commons-ssl.test.properties");
        if (f.exists()) {
            Properties p = new Properties();

            boolean loaded = false;
            FileInputStream fin = null;
            try {
                fin = new FileInputStream(f);
                p.load(fin);
                loaded = true;
            } catch (IOException ioe) {
                System.err.println("Failed to load: " + f);
            } finally {
                if (fin != null) {
                    try {
                        fin.close();
                    } catch (IOException ioe) {
                        System.err.println("Failed to close: " + f);
                    }
                }
            }

            if (loaded) {
                home = p.getProperty("commons-ssl.home");
                if (!home.endsWith("/")) {
                    home = home + "/";
                }
            }
        }
        TEST_HOME = home;
    }
}
