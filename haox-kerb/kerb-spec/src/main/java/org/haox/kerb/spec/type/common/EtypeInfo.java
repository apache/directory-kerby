package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.type.KrbType;
import org.haox.kerb.spec.type.SequenceOfType;

import java.util.List;

/**
 ETYPE-INFO              ::= SEQUENCE OF ETYPE-INFO-ENTRY
 */
public interface EtypeInfo extends SequenceOfType {
    public static Class<? extends KrbType> ElementType =  EtypeInfoEntry.class;

    public List<EtypeInfoEntry> getEntries();

    public void setEntries(List<EtypeInfoEntry> entries);
}
