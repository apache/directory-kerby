package org.haox.kerb.spec.type.common;

import org.haox.asn1.type.AbstractSequenceType;
import org.haox.asn1.type.Asn1Integer;
import org.haox.asn1.Asn1Tag;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KerberosStrings;

import java.util.Collections;
import java.util.List;

/**
 PrincipalName   ::= SEQUENCE {
 name-type       [0] Int32,
 name-string     [1] SEQUENCE OF KerberosString
 }
 */
public class PrincipalName extends AbstractSequenceType {
    public static final String TGS_DEFAULT_SRV_NAME = "krbtgt";
    public static final int TGS_DEFAULT_NT = 2;
    public static final char NAME_COMPONENT_SEPARATOR = '/';
    public static final char NAME_REALM_SEPARATOR = '@';
    public static final char REALM_COMPONENT_SEPARATOR = '.';
    public static final String NAME_COMPONENT_SEPARATOR_STR = "/";
    public static final String NAME_REALM_SEPARATOR_STR = "@";
    public static final String REALM_COMPONENT_SEPARATOR_STR = ".";

    private static int NAME_TYPE = 0;
    private static int NAME_STRING = 1;

    static Asn1Tag[] tags = new Asn1Tag[] {
            new Asn1Tag(NAME_TYPE, 0, Asn1Integer.class),
            new Asn1Tag(NAME_STRING, 1, KerberosStrings.class)
    };

    @Override
    protected Asn1Tag[] getTags() {
        return tags;
    }

    public NameType getNameType() throws KrbException {
        Integer value = getFieldAsInteger(NAME_TYPE);
        return NameType.fromValue(value);
    }

    public void setNameType(NameType nameType) throws KrbException {
        setFieldAsInt(NAME_STRING, nameType.getValue());
    }

    public List<String> getNameStrings() throws KrbException {
        KerberosStrings krbStrings = getFieldAs(NAME_STRING, KerberosStrings.class);
        if (krbStrings != null) {
            return krbStrings.getAsStrings();
        }
        return Collections.EMPTY_LIST;
    }

    public void setNameStrings(List<String> nameStrings) throws KrbException {
        setFieldAs(NAME_STRING, new KerberosStrings(nameStrings));
    }

    public String getNameRealm() {
        return null; //TODO: get realm from strings
    }

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
}
