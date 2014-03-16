package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.*;

import java.util.List;

/**
 PrincipalName   ::= SEQUENCE {
 name-type       [0] Int32,
 name-string     [1] SEQUENCE OF KerberosString
 }
 */
public interface PrincipalName extends SequenceType {
    public static final String TGS_DEFAULT_SRV_NAME = "krbtgt";
    public static final int TGS_DEFAULT_NT = 2;
    public static final char NAME_COMPONENT_SEPARATOR = '/';
    public static final char NAME_REALM_SEPARATOR = '@';
    public static final char REALM_COMPONENT_SEPARATOR = '.';
    public static final String NAME_COMPONENT_SEPARATOR_STR = "/";
    public static final String NAME_REALM_SEPARATOR_STR = "@";
    public static final String REALM_COMPONENT_SEPARATOR_STR = ".";

    public static enum Tag implements KrbTag {
        NAME_TYPE(0, KrbInteger.class),
        NAME_STRING(1, KrbStrings.class);

        private int value;
        private Class<? extends KrbType> type;

        private Tag(int value, Class<? extends KrbType> type) {
            this.value = value;
            this.type = type;
        }

        @Override
        public int getValue() {
            return value;
        }

        @Override
        public int getIndex() {
            return ordinal();
        }

        @Override
        public Class<? extends KrbType> getType() {
            return type;
        }
    };

    public NameType getNameType() throws KrbException;

    public void setNameType(NameType nameType) throws KrbException;

    public List<String> getNameStrings() throws KrbException;

    public void setNameStrings(List<String> nameStrings) throws KrbException;

    public String getNameRealm();

    public String getName() throws KrbException;
}
