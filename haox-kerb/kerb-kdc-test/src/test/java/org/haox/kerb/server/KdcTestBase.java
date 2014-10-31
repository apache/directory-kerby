package org.haox.kerb.server;

import org.haox.kerb.client.KrbClient;
import org.haox.kerb.spec.type.ticket.ServiceTicket;
import org.haox.kerb.spec.type.ticket.TgtTicket;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public abstract class KdcTestBase {

    protected String kdcRealm;
    protected String clientPrincipal;
    protected String serverPrincipal;

    protected String hostname = "localhost";
    protected short port = 8088;

    protected TestKdcServer kdcServer;
    protected KrbClient krbClnt;

    @Before
    public void setUp() throws Exception {
        setUpKdcServer();
        setUpClient();
    }

    protected void setUpKdcServer() {
        kdcServer = new TestKdcServer();
        kdcServer.setKdcHost(hostname);
        kdcServer.setKdcPort(port);
        kdcServer.init();

        kdcRealm = kdcServer.getKdcRealm();
        clientPrincipal = "drankye@" + kdcRealm;

        serverPrincipal = "test-service/localhost@" + kdcRealm;
        kdcServer.createPrincipals(serverPrincipal);
    }

    protected void setUpClient() {
        krbClnt = new KrbClient(hostname, port);
        krbClnt.setTimeout(5);
        krbClnt.setKdcRealm(kdcServer.getKdcRealm());
    }

    @After
    public void tearDown() throws Exception {
        kdcServer.stop();
    }
}