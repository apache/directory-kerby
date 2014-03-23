package org.haox.kerb.spec.type.common.impl;

import org.haox.kerb.codec.AbstractSequenceOfType;
import org.haox.kerb.spec.type.KrbType;
import org.haox.kerb.spec.type.common.PaData;
import org.haox.kerb.spec.type.common.PaDataEntry;

import java.util.List;

public class PaDataImpl extends AbstractSequenceOfType implements PaData {

    public List<PaDataEntry> getEntries() {
        return this.getElementsAs(PaDataEntry.class);
    }

    public void setEntries(List<PaDataEntry> entries) {
        elements.clear();
        elements.addAll(entries);
    }

    @Override
    public Class<? extends KrbType> getElementType() {
        return ElementType;
    }
}
