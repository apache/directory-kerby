package org.apache.kerberos.kerb.server;

import org.apache.kerberos.kerb.KrbException;
import org.apache.kerberos.kerb.spec.ticket.ServiceTicket;
import org.apache.kerberos.kerb.spec.ticket.TgtTicket;
import org.haox.token.KerbToken;
import org.junit.Assert;
import org.junit.Test;

public class WithTokenKdcTest extends KdcTestBase {

    private KerbToken token;

    @Override
    protected void setUpKdcServer() throws Exception {
        super.setUpKdcServer();
        kdcServer.createPrincipals(clientPrincipal);
    }

    //@Test
    public void testKdc() throws Exception {
        kdcServer.start();
        Assert.assertTrue(kdcServer.isStarted());
        krbClnt.init();

        TgtTicket tgt = null;
        try {
            tgt = krbClnt.requestTgtTicket(clientPrincipal, token, null);
        } catch (KrbException te) {
            Assert.assertTrue(te.getMessage().contains("timeout"));
            return;
        }
        Assert.assertNull(tgt);

        ServiceTicket tkt = krbClnt.requestServiceTicket(tgt, serverPrincipal, null);
        Assert.assertNull(tkt);
    }
}