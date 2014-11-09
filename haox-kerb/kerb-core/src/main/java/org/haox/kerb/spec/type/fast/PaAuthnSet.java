package org.haox.kerb.spec.type.fast;

import org.haox.kerb.spec.type.KrbSequenceOfType;
import org.haox.kerb.spec.type.pa.PaDataEntry;

/**
 PA-AUTHENTICATION-SET ::= SEQUENCE OF PA-AUTHENTICATION-SET-ELEM
 */
public class PaAuthnSet extends KrbSequenceOfType<PaAuthnEntry> {

}
