package org.haox.kerb.spec.type.common;

/**
 Checksum        ::= SEQUENCE {
 cksumtype       [0] Int32,
 checksum        [1] OCTET STRING
 }
 */
public class Checksum {
    private ChecksumType cksumtype;
    private byte[] checksum;

    public ChecksumType getCksumtype() {
        return cksumtype;
    }

    public void setCksumtype(ChecksumType cksumtype) {
        this.cksumtype = cksumtype;
    }

    public byte[] getChecksum() {
        return checksum;
    }

    public void setChecksum(byte[] checksum) {
        this.checksum = checksum;
    }
}
