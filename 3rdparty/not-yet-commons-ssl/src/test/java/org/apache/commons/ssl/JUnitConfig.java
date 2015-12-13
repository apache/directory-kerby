package org.apache.commons.ssl;

import java.io.File;
import java.net.URL;

public class JUnitConfig {

    public static final String TEST_HOME;

    static {
        URL url = JUnitConfig.class.getResource("/TEST-HOME");
        String homeTestPath = url.getFile();
        File homeTestFile = new File(homeTestPath);
        File homeDir = homeTestFile.getParentFile();

        TEST_HOME = homeDir.getAbsolutePath() + File.separator;
    }
}
