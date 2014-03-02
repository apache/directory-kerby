package org.haox.kerb.spec.type.common.impl;

import org.haox.kerb.codec.AbstractSequenceOfType;
import org.haox.kerb.spec.type.common.AuthorizationData;
import org.haox.kerb.spec.type.common.AuthorizationDataEntry;

import java.util.List;

public class AuthorizationDataImpl extends AbstractSequenceOfType implements AuthorizationData {

    public AuthorizationDataImpl() {
        super(AuthorizationDataEntry.class);
    }

    public List<AuthorizationDataEntry> getEntries() {
        return this.getElementsAs(AuthorizationDataEntry.class);
    }

    public void setEntries(List<AuthorizationDataEntry> entries) {
        this.setEntries(entries);
    }
}
