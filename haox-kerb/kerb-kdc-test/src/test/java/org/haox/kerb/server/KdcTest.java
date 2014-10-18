package org.haox.kerb.server;

import org.haox.kerb.client.KrbClient;
import org.haox.kerb.client.KrbConfig;
import org.haox.kerb.client.KrbConfigKey;
import org.haox.kerb.spec.type.ticket.TgtTicket;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.Properties;

public class KdcTest {

    private String clientPrincipal;
    private String password = "123456";
    private String hostname = "localhost";
    private short port = 8088;

    private TestKdcServer kdcServer;

    @Before
    public void setUp() throws Exception {
        kdcServer = new TestKdcServer();
        kdcServer.setKdcHost(hostname);
        kdcServer.setKdcPort(port);
        kdcServer.init();
        kdcServer.start();

        clientPrincipal = "drankye@" + kdcServer.getKdcRealm();
        kdcServer.createPrincipal(clientPrincipal, password);
    }

    @Test
    public void testKdc() throws Exception {
        Assert.assertTrue(kdcServer.isStarted());

        Properties props = new Properties();
        props.setProperty(KrbConfigKey.KDC_HOST.getPropertyKey(), hostname);
        props.setProperty(KrbConfigKey.KDC_PORT.getPropertyKey(), String.valueOf(port));
        props.setProperty(KrbConfigKey.KDC_REALM.getPropertyKey(), kdcServer.getKdcRealm());
        KrbConfig config = new KrbConfig();
        config.getConf().addPropertiesConfig(props);
        KrbClient krbClnt = new KrbClient(config);
        krbClnt.init();
        TgtTicket tgt = krbClnt.requestTgtTicket(clientPrincipal, password);
        Assert.assertNotNull(tgt);
    }

    @After
    public void tearDown() throws Exception {
        kdcServer.stop();
    }
}