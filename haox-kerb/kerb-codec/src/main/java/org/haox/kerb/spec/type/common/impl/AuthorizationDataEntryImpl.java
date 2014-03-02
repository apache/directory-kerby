package org.haox.kerb.spec.type.common.impl;

import org.haox.kerb.codec.AbstractSequenceType;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.KrbTypes;
import org.haox.kerb.spec.type.KrbInteger;
import org.haox.kerb.spec.type.KrbOctetString;
import org.haox.kerb.spec.type.KrbTag;
import org.haox.kerb.spec.type.common.AuthorizationDataEntry;
import org.haox.kerb.spec.type.common.AuthorizationType;

/**
 AuthorizationData       ::= SEQUENCE OF SEQUENCE {
 ad-type         [0] Int32,
 ad-data         [1] OCTET STRING
 }
 */
public class AuthorizationDataEntryImpl extends AbstractSequenceType implements AuthorizationDataEntry {
    public AuthorizationType getAuthzType() throws KrbException {
        KrbInteger value = getFieldAs(Tag.AD_TYPE, KrbInteger.class);
        return AuthorizationType.fromValue(value);
    }

    public void setAuthzType(AuthorizationType authzType) throws KrbException {
        setField(Tag.AD_TYPE, KrbTypes.makeInteger(authzType));
    }

    public byte[] getAuthzData() throws KrbException {
        KrbOctetString value = getFieldAs(Tag.AD_DATA, KrbOctetString.class);
        if (value != null) return value.getValue();
        return null;
    }

    public void setAuthzData(byte[] authzData) throws KrbException {
        KrbOctetString value = KrbTypes.makeOctetString(authzData);
        setField(Tag.AD_DATA, value);
    }

    @Override
    public KrbTag[] getTags() {
        return Tag.values();
    }
}
