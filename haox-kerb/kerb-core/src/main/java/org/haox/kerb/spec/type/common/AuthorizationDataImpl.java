package org.haox.kerb.spec.type.common;

import org.haox.kerb.codec.AbstractSequenceOfType;
import org.haox.kerb.spec.type.KrbType;
import org.haox.kerb.spec.type.common.AuthorizationData;
import org.haox.kerb.spec.type.common.AuthorizationDataEntry;

import java.util.List;

public class AuthorizationDataImpl extends AbstractSequenceOfType implements AuthorizationData {

    public List<AuthorizationDataEntry> getEntries() {
        return this.getElementsAs(AuthorizationDataEntry.class);
    }

    public void setEntries(List<AuthorizationDataEntry> entries) {
        elements.clear();
        elements.addAll(entries);
    }

    @Override
    public Class<? extends KrbType> getElementType() {
        return ElementType;
    }
}
