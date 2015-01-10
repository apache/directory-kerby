package org.apache.kerberos.kerb.codec.pac;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;

public class PacSignature {

    private int type;
    private byte[] checksum;

    public PacSignature(byte[] data) throws IOException {
        try {
            PacDataInputStream bufferStream = new PacDataInputStream(new DataInputStream(
                    new ByteArrayInputStream(data)));

            type = bufferStream.readInt();
            checksum = new byte[bufferStream.available()];
            bufferStream.readFully(checksum);
        } catch(IOException e) {
            throw new IOException("pac.signature.malformed", e);
        }
    }

    public int getType() {
        return type;
    }

    public byte[] getChecksum() {
        return checksum;
    }

}
