package org.haox.kerb.spec.type.common.impl;

import org.haox.kerb.codec.AbstractSequenceType;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.KrbTypes;
import org.haox.kerb.spec.type.KrbInteger;
import org.haox.kerb.spec.type.KrbStrings;
import org.haox.kerb.spec.type.KrbTag;
import org.haox.kerb.spec.type.common.NameType;
import org.haox.kerb.spec.type.common.PrincipalName;

import java.util.List;

public class PrincipalNameImpl extends AbstractSequenceType implements PrincipalName {
    public NameType getNameType() throws KrbException {
        KrbInteger value = getFieldAs(Tag.NAME_TYPE, KrbInteger.class);
        return NameType.fromValue(value);
    }

    public void setNameType(NameType nameType) throws KrbException {
        setField(Tag.NAME_STRING, KrbTypes.makeInteger(nameType));
    }

    public List<String> getNameStrings() throws KrbException {
        KrbStrings value = getFieldAs(Tag.NAME_STRING, KrbStrings.class);
        return value.getValues();
    }

    public void setNameStrings(List<String> nameStrings) throws KrbException {
        setField(Tag.NAME_STRING, KrbTypes.makeStrings(nameStrings));
    }

    @Override
    public String getNameRealm() {
        return null; //TODO: get realm from strings
    }

    @Override
    public String getName() throws KrbException {
        List<String> names = getNameStrings();
        StringBuffer sb = new StringBuffer();
        boolean isFirst = true;
        for (String name : names) {
            sb.append(name);
            if (isFirst && names.size() > 1) {
                sb.append("/");
            }
            isFirst = false;
        }

        String realm = getNameRealm();
        if (realm != null && !realm.isEmpty()) {
            sb.append("@");
            sb.append(realm);
        }

        return sb.toString();
    }

    @Override
    public KrbTag[] getTags() {
        return Tag.values();
    }
}
