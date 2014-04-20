package org.haox.kerb.server;

import org.junit.After;
import org.junit.Before;

import java.io.File;
import java.util.Properties;

public class KdcTestBase {
    private TestKdcServer kdc;
    private File testDir;
    private Properties conf;

    @Before
    public void startTestKdc() throws Exception {
        kdc = new TestKdcServer(conf);
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

    protected void setTestDir(File testDir) {
        this.testDir = testDir;
        File workDir = new File(testDir, "testkdc_run");
        conf.setProperty(TestKdcServer.WORK_DIR, workDir.getAbsolutePath());
    }

    public File getWorkDir() {
        return new File(getKdc().getConfig().getWorkDir());
    }

    public String getKdcRealm() {
        return "TEST.COM";
    }

    public String getKdcHost() {
        return "localhost";
    }

    public short getKdcPort() {
        return 8015;
    }
}
