package org.haox.kerb.crypto.checksum;

import org.haox.kerb.crypto2.KeyUsage;
import org.haox.kerb.spec.type.common.CheckSumType;

import java.util.zip.CRC32;

class Crc32Checksum implements ChecksumEngine
{
    public CheckSumType checksumType()
    {
        return CheckSumType.CRC32;
    }


    public byte[] calculateChecksum( byte[] data, byte[] key, KeyUsage usage )
    {
        CRC32 crc32 = new CRC32();
        crc32.update( data );

        return int2octet( ( int ) crc32.getValue() );
    }


    private byte[] int2octet( int value )
    {
        byte[] bytes = new byte[4];
        int i, shift;

        for ( i = 0, shift = 24; i < 4; i++, shift -= 8 )
        {
            bytes[i] = ( byte ) ( 0xFF & ( value >> shift ) );
        }

        return bytes;
    }
}
