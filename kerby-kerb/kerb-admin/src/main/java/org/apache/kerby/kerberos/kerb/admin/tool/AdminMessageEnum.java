package org.apache.kerby.kerberos.kerb.admin.tool;

import org.apache.kerby.xdr.EnumType;
import org.apache.kerby.xdr.type.XdrEnumerated;

/**
 * An extend XdrEnumerate to encode and decode AdminMessageType.
 */
public class AdminMessageEnum extends XdrEnumerated<AdminMessageType> {

    public AdminMessageEnum() {
        super(null);
    }

    public AdminMessageEnum(AdminMessageType value) {
        super(value);
    }
    @Override
    protected EnumType[] getAllEnumValues() {
        return AdminMessageType.values();
    }

}