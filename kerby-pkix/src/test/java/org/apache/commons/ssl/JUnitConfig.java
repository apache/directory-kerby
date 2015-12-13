package org.apache.commons.ssl;

import java.io.File;
import java.net.URL;

public class JUnitConfig {

    public static final String TEST_HOME;

    static {
        URL url = JUnitConfig.class.getResource("/not-so-commons-ssl");
        String tmpPath = url.getFile();
        File homeDir = new File(tmpPath);
        TEST_HOME = homeDir.getAbsolutePath() + File.separator;
    }
}
