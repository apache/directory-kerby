package org.haox.kerb.spec.type.common;

/**
 PA-DATA         ::= SEQUENCE {
 -- NOTE: first tag is [1], not [0]
 padata-type     [1] Int32,
 padata-value    [2] OCTET STRING -- might be encoded AP-REQ
 }
 */
public class PaData {
    private PaDataType paDataType;
    private byte[] paDataValue;

    public PaDataType getPaDataType() {
        return paDataType;
    }

    public void setPaDataType(PaDataType paDataType) {
        this.paDataType = paDataType;
    }

    public byte[] getPaDataValue() {
        return paDataValue;
    }

    public void setPaDataValue(byte[] paDataValue) {
        this.paDataValue = paDataValue;
    }
}
