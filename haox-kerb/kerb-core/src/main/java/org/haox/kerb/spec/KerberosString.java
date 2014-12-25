package org.haox.kerb.spec;

import org.haox.asn1.type.Asn1GeneralString;

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
