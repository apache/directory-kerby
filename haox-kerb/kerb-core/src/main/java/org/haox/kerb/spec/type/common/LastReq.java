package org.haox.kerb.spec.type.common;

import org.haox.asn1.type.SequenceOfType;

/**
 LastReq         ::=     SEQUENCE OF SEQUENCE {
 lr-type         [0] Int32,
 lr-value        [1] KerberosTime
 }
 */
public class LastReq extends SequenceOfType<LastReqEntry> {

}
