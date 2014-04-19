package org.haox.kerb.spec.type.common;

import org.haox.asn1.type.SequenceOfType;

/**
 AuthorizationData       ::= SEQUENCE OF SEQUENCE {
 ad-type         [0] Int32,
 ad-data         [1] OCTET STRING
 }
 */
public class AuthorizationData extends SequenceOfType<AuthorizationDataEntry> {

}
