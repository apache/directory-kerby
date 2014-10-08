package org.haox.kerb.server;

import org.haox.kerb.client.KrbClient;
import org.haox.kerb.spec.type.ticket.TgtTicket;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class KdcTest {

    private String clientPrincipal = "drankye@EXAMPLE.COM";
    private String password = "123456";
    private String hostname = "localhost";
    private short port = 8088;

    private SimpleKdcServer kdcServer;

    @Before
    public void setUp() throws Exception {
        kdcServer = new SimpleKdcServer();
        kdcServer.init();
        kdcServer.start();
    }

    @Test
    public void testKdc() throws Exception {
        Assert.assertTrue(kdcServer.isStarted());

        KrbClient krbClnt = new KrbClient(hostname, port);
        TgtTicket tgt = krbClnt.requestTgtTicket(clientPrincipal, password);
        Assert.assertNotNull(tgt);
    }

    @After
    public void tearDown() throws Exception {
        kdcServer.stop();
    }
}