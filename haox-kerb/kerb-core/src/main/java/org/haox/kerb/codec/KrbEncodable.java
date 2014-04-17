package org.haox.kerb.codec;

import org.haox.kerb.spec.KrbException;

public interface KrbEncodable {
    public byte[] encode() throws KrbException;
    public void decode(byte[] content) throws KrbException;
}
