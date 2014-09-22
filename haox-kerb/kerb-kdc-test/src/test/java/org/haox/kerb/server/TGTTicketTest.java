package org.haox.kerb.server;

import junit.framework.Assert;
import org.haox.kerb.spec.type.ticket.TgtTicket;
import org.junit.Test;

public class TGTTicketTest {

    //@Test
    public void testTGT() {
        String principal = "drankye@EXAMPLE.COM";
        TgtTicket tgt = new TgtTicket(null, null, null);
        //tgt.setClientPrincipal(principal);
        Assert.assertEquals(tgt.getClientPrincipal(), principal);
    }
}
