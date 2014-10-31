package org.haox.kerb.server;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.ticket.ServiceTicket;
import org.haox.kerb.spec.type.ticket.TgtTicket;
import org.junit.Assert;
import org.junit.Test;

import java.security.cert.Certificate;

public class WithCertKdcTest extends KdcTestBase {

    private Certificate cert;

    @Override
    protected void setUpKdcServer() {
        super.setUpKdcServer();
        kdcServer.createPrincipals(clientPrincipal);
    }

    @Test
    public void testKdc() throws Exception {
        kdcServer.start();
        Assert.assertTrue(kdcServer.isStarted());
        krbClnt.init();

        TgtTicket tgt = null;
        try {
            tgt = krbClnt.requestTgtTicket(clientPrincipal, cert);
        } catch (KrbException te) {
            Assert.assertTrue(te.getMessage().contains("timeout"));
            return;
        }
        Assert.assertNull(tgt);

        ServiceTicket tkt = krbClnt.requestServiceTicket(tgt, serverPrincipal);
        Assert.assertNull(tkt);
    }
}