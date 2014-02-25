package org.haox.kerb.spec.type.common;

import java.util.List;

public class PrincipalName {
    public static final String TGS_DEFAULT_SRV_NAME = "krbtgt";
    public static final int TGS_DEFAULT_NT = 2;
    public static final char NAME_COMPONENT_SEPARATOR = '/';
    public static final char NAME_REALM_SEPARATOR = '@';
    public static final char REALM_COMPONENT_SEPARATOR = '.';
    public static final String NAME_COMPONENT_SEPARATOR_STR = "/";
    public static final String NAME_REALM_SEPARATOR_STR = "@";
    public static final String REALM_COMPONENT_SEPARATOR_STR = ".";

    private KrbNameType nameType = KrbNameType.KRB_NT_UNKNOWN;
    private List<String> nameStrings;
    private String nameRealm;

    public KrbNameType getNameType() {
        return nameType;
    }

    public void setNameType(KrbNameType nameType) {
        this.nameType = nameType;
    }

    public List<String> getNameStrings() {
        return nameStrings;
    }

    public void setNameStrings(List<String> nameStrings) {
        this.nameStrings = nameStrings;
    }

    public String getNameRealm() {
        return nameRealm;
    }

    public void setNameRealm(String nameRealm) {
        this.nameRealm = nameRealm;
    }
}
