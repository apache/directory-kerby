package org.haox.kerb.server;

import junit.framework.Assert;
import org.haox.kerb.base.Ticket;
import org.haox.kerb.base.TicketGrantingTicket;
import org.junit.Test;

public class TGTTicketTest {

    @Test
    public void testTGT() {
        String principal = "drankye@EXAMPLE.COM";
        TicketGrantingTicket tgt = new TicketGrantingTicket();
        tgt.setClientPrincipal(principal);
        Assert.assertEquals(tgt.getClientPrincipal(), principal);
    }
}
