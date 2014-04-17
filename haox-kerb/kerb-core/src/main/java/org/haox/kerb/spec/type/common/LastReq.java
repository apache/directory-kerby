package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.type.KrbType;
import org.haox.kerb.spec.type.SequenceOfType;

import java.util.List;

/**
 LastReq         ::=     SEQUENCE OF SEQUENCE {
 lr-type         [0] Int32,
 lr-value        [1] KrbTime
 }
 */
public interface LastReq extends SequenceOfType {
    public static Class<? extends KrbType> ElementType =  LastReqEntry.class;

    public List<LastReqEntry> getEntries();

    public void setEntries(List<LastReqEntry> entries);
}
