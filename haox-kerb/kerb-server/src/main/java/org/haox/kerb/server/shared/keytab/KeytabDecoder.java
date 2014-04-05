package org.haox.kerb.server.shared.keytab;

import org.haox.kerb.server.shared.crypto.encryption.EncryptionUtil;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.common.KrbTime;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;


/**
 * Decode a {@link java.nio.ByteBuffer} into keytab fields.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
class KeytabDecoder
{
    /**
     * Read the keytab 16-bit file format version.  This
     * keytab reader currently only supports version 5.2.
     */
    byte[] getKeytabVersion( ByteBuffer buffer )
    {
        byte[] version = new byte[2];
        buffer.get( version );

        return version;
    }


    /**
     * Read keytab entries until there is no remaining data
     * in the buffer.
     *
     * @param buffer
     * @return The keytab entries.
     */
    List<KeytabEntry> getKeytabEntries( ByteBuffer buffer ) throws KrbException {
        List<KeytabEntry> entries = new ArrayList<KeytabEntry>();

        while ( buffer.remaining() > 0 )
        {
            int size = buffer.getInt();
            byte[] entry = new byte[size];

            buffer.get( entry );
            entries.add( getKeytabEntry( ByteBuffer.wrap( entry ) ) );
        }

        return entries;
    }


    /**
     * Reads off a "keytab entry," which consists of a principal name,
     * principal type, key version number, and key material.
     */
    private KeytabEntry getKeytabEntry( ByteBuffer buffer ) throws KrbException {
        String principalName = getPrincipalName( buffer );

        long principalType = buffer.getInt();

        long time = buffer.getInt();
        KrbTime timeStamp = new KrbTime( time * 1000 );

        byte keyVersion = buffer.get();

        EncryptionKey key = getKeyBlock( buffer );

        return new KeytabEntry( principalName, principalType, timeStamp, keyVersion, key );
    }


    /**
     * Reads off a principal name.
     *
     * @param buffer
     * @return The principal name.
     */
    private String getPrincipalName( ByteBuffer buffer )
    {
        int count = buffer.getShort();

        // decrement for v1
        String realm = getCountedString( buffer );

        StringBuffer principalNameBuffer = new StringBuffer();

        for ( int ii = 0; ii < count; ii++ )
        {
            String nameComponent = getCountedString( buffer );

            principalNameBuffer.append( nameComponent );

            if ( ii < count - 1 )
            {
                principalNameBuffer.append( "/" );
            }
        }

        principalNameBuffer.append( "@" ).append( realm );

        return principalNameBuffer.toString();
    }


    /**
     * Read off a 16-bit encryption type and symmetric key material.
     */
    private EncryptionKey getKeyBlock( ByteBuffer buffer ) throws KrbException {
        int type = buffer.getShort();
        byte[] keyblock = getCountedBytes( buffer );

        EncryptionType encryptionType = EncryptionType.fromValue(type);
        EncryptionKey key = EncryptionUtil.createEncryptionKey(encryptionType, keyblock );

        return key;
    }


    /**
     * Use a prefixed 16-bit length to read off a String.  Realm and name
     * components are ASCII encoded text with no zero terminator.
     */
    private String getCountedString( ByteBuffer buffer )
    {
        int length = buffer.getShort();
        byte[] data = new byte[length];
        buffer.get( data );

        try
        {
            return new String( data, "ASCII" );
        }
        catch ( UnsupportedEncodingException uee )
        {
            // Should never happen for ASCII
            return "";
        }
    }


    /**
     * Use a prefixed 16-bit length to read off raw bytes.
     */
    private byte[] getCountedBytes( ByteBuffer buffer )
    {
        int length = buffer.getShort();
        byte[] data = new byte[length];
        buffer.get( data );

        return data;
    }
}
