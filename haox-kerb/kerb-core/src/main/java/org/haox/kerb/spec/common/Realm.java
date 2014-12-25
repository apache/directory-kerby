package org.haox.kerb.spec.common;

import org.haox.kerb.spec.KerberosString;

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
