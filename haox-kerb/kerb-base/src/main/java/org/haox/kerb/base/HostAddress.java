package org.haox.kerb.base;

public class HostAddress {
    private HostAddrType addrType;
    private byte[] address;

    public HostAddrType getAddrType() {
        return addrType;
    }

    public void setAddrType(HostAddrType addrType) {
        this.addrType = addrType;
    }

    public byte[] getAddress() {
        return address;
    }

    public void setAddress(byte[] address) {
        this.address = address;
    }
}
