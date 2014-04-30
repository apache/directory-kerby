package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.type.KrbSequenceOfType;

/**
 AuthorizationData       ::= SEQUENCE OF SEQUENCE {
 ad-type         [0] Int32,
 ad-data         [1] OCTET STRING
 }
 */
public class AuthorizationData extends KrbSequenceOfType<AuthorizationDataEntry> {

}
