package org.haox.kerb.server;

import org.haox.kerb.client.KrbClient;
import org.haox.kerb.spec.type.ticket.ServiceTicket;
import org.haox.kerb.spec.type.ticket.TgtTicket;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class KdcTest {

    private String kdcRealm;
    private String clientPrincipal;
    private String password = "123456";
    private String serverPrincipal;

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

        kdcRealm = kdcServer.getKdcRealm();
        clientPrincipal = "drankye@" + kdcRealm;
        kdcServer.createPrincipal(clientPrincipal, password);

        serverPrincipal = "test-service/localhost@" + kdcRealm;
        kdcServer.createPrincipals(serverPrincipal);
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

        //ServiceTicket tkt = krbClnt.requestServiceTicket(tgt, serverPrincipal);
        //Assert.assertNotNull(tkt);
    }

    @After
    public void tearDown() throws Exception {
        kdcServer.stop();
    }
}