package org.haox.kerb.base;

/**
 TransitedEncoding       ::= SEQUENCE {
 tr-type         [0] Int32 -- must be registered --,
 contents        [1] OCTET STRING
 }
 */
public class TransitedEncoding {
    private TransitedEncodingType trType;
    private byte[] contents;

    public TransitedEncodingType getTrType() {
        return trType;
    }

    public void setTrType(TransitedEncodingType trType) {
        this.trType = trType;
    }

    public byte[] getContents() {
        return contents;
    }

    public void setContents(byte[] contents) {
        this.contents = contents;
    }
}
