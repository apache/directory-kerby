package org.haox.kerb.spec.pa.pkinit;

import org.apache.haox.asn1.type.Asn1FieldInfo;
import org.haox.kerb.spec.KrbSequenceType;
import org.haox.kerb.spec.common.PrincipalName;
import org.haox.kerb.spec.common.Realm;

/**
 KRB5PrincipalName ::= SEQUENCE {
     realm                   [0] Realm,
     principalName           [1] PrincipalName
 }
 */
public class Krb5PrincipalName extends KrbSequenceType {
    private static int REALM = 0;
    private static int PRINCIPAL_NAME = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(REALM, Realm.class),
            new Asn1FieldInfo(PRINCIPAL_NAME, PrincipalName.class)
    };

    public Krb5PrincipalName() {
        super(fieldInfos);
    }

    public String getRelm() {
        return getFieldAsString(REALM);
    }

    public void setRealm(String realm) {
        setFieldAsString(REALM, realm);
    }

    public PrincipalName getPrincipalName() {
        return getFieldAs(PRINCIPAL_NAME, PrincipalName.class);
    }

    public void setPrincipalName(PrincipalName principalName) {
        setFieldAs(PRINCIPAL_NAME, principalName);
    }
}
