package org.haox.kerb.spec.type.common.impl;

import org.haox.kerb.codec.AbstractKrbType;
import org.haox.kerb.codec.KrbEncodable;
import org.haox.kerb.spec.type.common.ChecksumType;
import org.haox.kerb.spec.type.common.MyChecksum;

public class MyChecksumImpl extends AbstractKrbType implements MyChecksum {
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
