package org.apache.kerberos.kerb.codec.pac;

import java.io.IOException;

public class PacUnicodeString {

    private short length;
    private short maxLength;
    private int pointer;

    public PacUnicodeString(short length, short maxLength, int pointer) {
        super();
        this.length = length;
        this.maxLength = maxLength;
        this.pointer = pointer;
    }

    public short getLength() {
        return length;
    }

    public short getMaxLength() {
        return maxLength;
    }

    public int getPointer() {
        return pointer;
    }

    public String check(String string) throws IOException {
        if(pointer == 0 && string != null)
            throw new IOException("pac.string.notempty");

        int expected = length / 2;
        if(string.length() != expected) {
            Object[] args = new Object[]{expected, string.length()};
            throw new IOException("pac.string.invalid.size");
        }

        return string;
    }
}
