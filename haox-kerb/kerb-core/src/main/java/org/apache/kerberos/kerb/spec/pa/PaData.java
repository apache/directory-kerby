package org.apache.kerberos.kerb.spec.pa;

import org.apache.kerberos.kerb.spec.KrbSequenceOfType;

/**
 PA-DATA         ::= SEQUENCE {
     -- NOTE: first tag is [1], not [0]
     padata-type     [1] Int32,
     padata-value    [2] OCTET STRING -- might be encoded AP-REQ
 }
 */
public class PaData extends KrbSequenceOfType<PaDataEntry> {

    public PaDataEntry findEntry(PaDataType paType) {
        for (PaDataEntry pae : getElements()) {
            if (pae.getPaDataType() == paType) {
                return pae;
            }
        }
        return null;
    }
}
