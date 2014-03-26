package org.haox.kerb.server.shared.crypto.checksum;

import org.haox.kerb.server.shared.crypto.KeyUsage;

public interface ChecksumEngine
{
    /**
     * Returns the checksum type of this checksum engine.
     *
     * @return The checksum type.
     */
    org.haox.kerb.spec.type.common.ChecksumType checksumType();


    /**
     * Calculate a checksum given raw bytes and an (optional) key.
     *
     * @param data
     * @param key
     * @param usage 
     * @return The checksum value.
     */
    byte[] calculateChecksum(byte[] data, byte[] key, KeyUsage usage);
}
