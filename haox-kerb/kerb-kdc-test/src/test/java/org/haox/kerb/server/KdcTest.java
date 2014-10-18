package org.haox.kerb.server;

import org.haox.kerb.client.KrbClient;
import org.haox.kerb.spec.type.ticket.TgtTicket;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class KdcTest {

    private String clientPrincipal;
    private String password = "123456";
    private String hostname = "localhost";
    private short port = 8088;

    private TestKdcServer kdcServer;
    private KrbClient krbClnt;

    @Before
    public void setUp() throws Exception {
        setUpKdcServer();
        setUpClient();
    }

    private void setUpKdcServer() {
        kdcServer = new TestKdcServer();
        kdcServer.setKdcHost(hostname);
        kdcServer.setKdcPort(port);
        kdcServer.init();

        clientPrincipal = "drankye@" + kdcServer.getKdcRealm();
        kdcServer.createPrincipal(clientPrincipal, password);
    }

    private void setUpClient() {
        krbClnt = new KrbClient(hostname, port);
        krbClnt.setKdcRealm(kdcServer.getKdcRealm());
    }

    @Test
    public void testKdc() throws Exception {
        kdcServer.start();
        Assert.assertTrue(kdcServer.isStarted());

        krbClnt.init();
        TgtTicket tgt = krbClnt.requestTgtTicket(clientPrincipal, password);
        Assert.assertNotNull(tgt);
    }

    @After
    public void tearDown() throws Exception {
        kdcServer.stop();
    }
}