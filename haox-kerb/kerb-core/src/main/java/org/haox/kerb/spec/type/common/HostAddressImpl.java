package org.haox.kerb.spec.type.common;

import org.haox.kerb.codec.AbstractSequenceType;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.KrbTypes;
import org.haox.kerb.spec.type.KrbInteger;
import org.haox.kerb.spec.type.KrbOctetString;
import org.haox.kerb.spec.type.KrbTag;
import org.haox.kerb.spec.type.common.HostAddrType;
import org.haox.kerb.spec.type.common.HostAddress;

public class HostAddressImpl extends AbstractSequenceType implements HostAddress {
    public HostAddrType getAddrType() throws KrbException {
        KrbInteger value = getFieldAs(Tag.ADDR_TYPE, KrbInteger.class);
        return HostAddrType.fromValue(value);
    }

    public void setAddrType(HostAddrType addrType) throws KrbException {
        setField(Tag.ADDR_TYPE, KrbTypes.makeInteger(addrType));
    }

    public byte[] getAddress() throws KrbException {
        KrbOctetString value = getFieldAs(Tag.ADDRESS, KrbOctetString.class);
        if (value != null) return value.getValue();
        return null;
    }

    public void setAddress(byte[] address) throws KrbException {
        KrbOctetString value = KrbTypes.makeOctetString(address);
        setField(Tag.ADDRESS, value);
    }

    @Override
    public KrbTag[] getTags() {
        return Tag.values();
    }
}
