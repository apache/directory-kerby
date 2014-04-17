package org.haox.kerb.spec.type.common;

import org.haox.kerb.codec.AbstractSequenceOfType;
import org.haox.kerb.spec.type.KrbType;
import org.haox.kerb.spec.type.common.AuthorizationData;
import org.haox.kerb.spec.type.common.AuthorizationDataEntry;
import org.haox.kerb.spec.type.common.HostAddress;
import org.haox.kerb.spec.type.common.HostAddresses;

import java.util.List;

public class HostAddressesImpl extends AbstractSequenceOfType implements HostAddresses {

    public List<HostAddress> getAddresses() {
        return this.getElementsAs(HostAddress.class);
    }

    public void setAddresses(List<HostAddress> addresses) {
        elements.clear();
        elements.addAll(addresses);
    }

    @Override
    public Class<? extends KrbType> getElementType() {
        return ElementType;
    }
}
