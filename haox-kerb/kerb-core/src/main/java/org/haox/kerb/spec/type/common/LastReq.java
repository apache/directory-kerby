package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.type.KrbSequenceOfType;

/**
 LastReq         ::=     SEQUENCE OF SEQUENCE {
 lr-type         [0] Int32,
 lr-value        [1] KerberosTime
 }
 */
public class LastReq extends KrbSequenceOfType<LastReqEntry> {

}
