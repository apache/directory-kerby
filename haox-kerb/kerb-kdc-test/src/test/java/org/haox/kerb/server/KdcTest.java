package org.haox.kerb.server;

import org.haox.kerb.spec.type.ticket.ServiceTicket;
import org.haox.kerb.spec.type.ticket.TgtTicket;
import org.junit.Assert;
import org.junit.Test;

public class KdcTest extends KdcTestBase {

    private String password = "123456";

    @Override
    protected void setUpKdcServer() throws Exception {
        super.setUpKdcServer();
        kdcServer.createPrincipal(clientPrincipal, password);
    }

    @Test
    public void testKdc() throws Exception {
        kdcServer.start();
        Assert.assertTrue(kdcServer.isStarted());

        krbClnt.init();
        TgtTicket tgt = krbClnt.requestTgtTicket(clientPrincipal, password, null);
        Assert.assertNotNull(tgt);

        ServiceTicket tkt = krbClnt.requestServiceTicket(tgt, serverPrincipal, null);
        Assert.assertNotNull(tkt);
    }
}