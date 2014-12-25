package org.apache.kerberos.kerb.spec.common;

import org.apache.kerberos.kerb.spec.KerberosString;

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
