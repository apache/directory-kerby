package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.type.KrbType;
import org.haox.kerb.spec.type.SequenceOfType;

import java.util.List;

/**
 AuthorizationData       ::= SEQUENCE OF SEQUENCE {
 ad-type         [0] Int32,
 ad-data         [1] OCTET STRING
 }
 */
public interface AuthorizationData extends SequenceOfType {
    public static Class<? extends KrbType> ElementType =  AuthorizationDataEntry.class;

    public List<AuthorizationDataEntry> getEntries();

    public void setEntries(List<AuthorizationDataEntry> entries);
}
