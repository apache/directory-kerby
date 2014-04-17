package org.haox.kerb.spec.type.ticket;

import org.haox.kerb.spec.type.KrbType;
import org.haox.kerb.spec.type.SequenceOfType;

import java.util.List;

/**
 SEQUENCE OF Ticket
 */
public interface Tickets extends SequenceOfType {
    public static Class<? extends KrbType> ElementType =  Ticket.class;

    public List<Ticket> getEntries();

    public void setEntries(List<Ticket> entries);
}
