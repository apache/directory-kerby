package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.type.KrbSequenceOfType;

/**
 PA-DATA         ::= SEQUENCE {
 -- NOTE: first tag is [1], not [0]
 padata-type     [1] Int32,
 padata-value    [2] OCTET STRING -- might be encoded AP-REQ
 }
 */
public class PaData extends KrbSequenceOfType<PaDataEntry> {

}
