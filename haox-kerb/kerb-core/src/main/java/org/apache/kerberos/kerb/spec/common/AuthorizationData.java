package org.apache.kerberos.kerb.spec.common;

import org.apache.kerberos.kerb.spec.KrbSequenceOfType;

/**
 AuthorizationData       ::= SEQUENCE OF SEQUENCE {
 ad-type         [0] Int32,
 ad-data         [1] OCTET STRING
 }
 */
public class AuthorizationData extends KrbSequenceOfType<AuthorizationDataEntry> {

}
