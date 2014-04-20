package org.haox.kerb.server;

import org.junit.After;
import org.junit.Before;

import java.io.File;
import java.util.Properties;

public class KdcTestBase {
    private TestKdcServer kdc;
    private File workDir;
    private Properties conf;

    @Before
    public void startTestKdc() throws Exception {
        kdc = new TestKdcServer(conf, workDir);
        kdc.start();
    }

    @After
    public void stopTestKdc() {
        if (kdc != null) {
            kdc.stop();
        }
    }

    protected TestKdcServer getKdc() {
        return kdc;
    }

    protected File getTestDir() {
        return new File(System.getProperty("test.dir", "target"));
    }

    protected String getKdcRealm() {
        return "TEST.COM";
    }

    protected String getKdcHost() {
        return "localhost";
    }

    protected short getKdcPort() {
        return 8015;
    }
}
