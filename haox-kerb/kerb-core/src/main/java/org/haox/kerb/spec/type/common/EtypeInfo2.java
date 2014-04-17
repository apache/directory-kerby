package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.type.KrbType;
import org.haox.kerb.spec.type.SequenceOfType;

import java.util.List;

/**
 ETYPE-INFO2             ::= SEQUENCE SIZE (1..MAX) OF ETYPE-INFO2-ENTRY
 */
public interface EtypeInfo2 extends SequenceOfType {
    public static Class<? extends KrbType> ElementType =  EtypeInfo2Entry.class;

    public List<EtypeInfo2Entry> getEntries();

    public void setEntries(List<EtypeInfo2Entry> entries);
}
