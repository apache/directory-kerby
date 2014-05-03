package org.haox.kerb.spec.type;

import org.haox.asn1.type.Asn1GeneralString;
import org.haox.asn1.type.Asn1IA5String;

/**
 KerberosString  ::= GeneralString -- (IA5String)
 */
public class KerberosString extends Asn1GeneralString {
    public KerberosString() {
    }

    public KerberosString(String value) {
        super(value);
    }
}
