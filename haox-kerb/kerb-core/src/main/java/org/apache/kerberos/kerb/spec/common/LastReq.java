package org.apache.kerberos.kerb.spec.common;

import org.apache.kerberos.kerb.spec.KrbSequenceOfType;

/**
 LastReq         ::=     SEQUENCE OF SEQUENCE {
 lr-type         [0] Int32,
 lr-value        [1] KerberosTime
 }
 */
public class LastReq extends KrbSequenceOfType<LastReqEntry> {

}
