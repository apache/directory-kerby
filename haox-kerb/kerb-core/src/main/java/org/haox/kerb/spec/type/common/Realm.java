package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.type.KerberosString;

/**
 * Realm           ::= KerberosString
 */
public class Realm extends KerberosString {
    public Realm() {
    }

    public Realm(String value) {
        super(value);
    }
}
