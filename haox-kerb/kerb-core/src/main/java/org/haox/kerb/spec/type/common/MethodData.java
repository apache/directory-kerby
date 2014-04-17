package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.type.KrbType;
import org.haox.kerb.spec.type.SequenceOfType;

import java.util.List;

/**
 METHOD-DATA     ::= SEQUENCE OF PA-DATA
 */
public interface MethodData extends SequenceOfType {
    public static Class<? extends KrbType> ElementType =  PaDataEntry.class;

    public List<PaDataEntry> getEntries();

    public void setEntries(List<PaDataEntry> entries);
}
