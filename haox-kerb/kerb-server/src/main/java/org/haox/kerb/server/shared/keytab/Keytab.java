package org.haox.kerb.server.shared.keytab;

import org.apache.directory.server.i18n.I18n;
import org.haox.kerb.spec.KrbException;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Keytab file. The format is the following :
 * <pre>
 * { 
 *   version : 2 bytes (0x05 0x02)
 *   keytabEntry*
 * }
 *
 * keytab_entry 
 * {
 *     size : int
 *     numComponents :  short
 *     realm : countedOctetString
 *     components[numComponents] : countedOctetString
 *     nameType : int
 *     timestamp : int
 *     vno8 : byte
 *     key : keyBlock
 *     vno : int // only present if >= 4 bytes left in entry
 * };
 *
 * keyblock 
 * {
 *     type : int
 *     data : countedOctetString
 * }
 *
 * countedOctetString 
 * {
 *     length : short
 *     data[length] : bytes
 * }
 */
public class Keytab
{
    /**
     * Byte array constant for keytab file format 5.1.
     */
    public static final byte[] VERSION_0X501_BYTES = new byte[]
        { ( byte ) 0x05, ( byte ) 0x01 };

    // Format 0x0501
    public static final short VERSION_0X501 = 0x0501;

    /**
     * Byte array constant for keytab file format 5.2.
     */
    public static final byte[] VERSION_0X502_BYTES = new byte[]
        { ( byte ) 0x05, ( byte ) 0x02 };

    // Format 0x0502
    public static final short VERSION_0X502 = 0x0502;

    private byte[] keytabVersion = VERSION_0X502_BYTES;
    private List<KeytabEntry> entries = new ArrayList<KeytabEntry>();


    /**
     * Read a keytab file.
     *
     * @param file
     * @return The keytab.
     * @throws java.io.IOException
     */
    public static Keytab read( File file ) throws IOException, KrbException {
        ByteBuffer buffer = ByteBuffer.wrap( getBytesFromFile( file ) );
        return readKeytab( buffer );
    }


    /**
     * Returns a new instance of a keytab with the version
     * defaulted to 5.2.
     *
     * @return The keytab.
     */
    public static Keytab getInstance()
    {
        return new Keytab();
    }


    /**
     * Write the keytab to a {@link java.io.File}.
     *
     * @param file
     * @throws java.io.IOException
     */
    public void write( File file ) throws IOException, KrbException {
        KeytabEncoder writer = new KeytabEncoder();
        ByteBuffer buffer = writer.write( keytabVersion, entries );
        writeFile( buffer, file );
    }


    /**
     * @param entries The entries to set.
     */
    public void setEntries( List<KeytabEntry> entries )
    {
        this.entries = entries;
    }


    /**
     * @param keytabVersion The keytabVersion to set.
     */
    public void setKeytabVersion( byte[] keytabVersion )
    {
        this.keytabVersion = keytabVersion;
    }


    /**
     * @return The entries.
     */
    public List<KeytabEntry> getEntries()
    {
        return Collections.unmodifiableList( entries );
    }


    /**
     * @return The keytabVersion.
     */
    public byte[] getKeytabVersion()
    {
        return keytabVersion;
    }


    /**
     * Read bytes into a keytab.
     *
     * @param bytes
     * @return The keytab.
     */
    static Keytab read( byte[] bytes ) throws KrbException {
        ByteBuffer buffer = ByteBuffer.wrap( bytes );
        return readKeytab( buffer );
    }


    /**
     * Write the keytab to a {@link java.nio.ByteBuffer}.
     * @return The buffer.
     */
    ByteBuffer write() throws KrbException {
        KeytabEncoder writer = new KeytabEncoder();
        return writer.write( keytabVersion, entries );
    }


    /**
     * Read the contents of the buffer into a keytab.
     *
     * @param buffer
     * @return The keytab.
     */
    private static Keytab readKeytab( ByteBuffer buffer ) throws KrbException {
        KeytabDecoder reader = new KeytabDecoder();
        byte[] keytabVersion = reader.getKeytabVersion( buffer );
        List<KeytabEntry> entries = reader.getKeytabEntries( buffer );

        Keytab keytab = new Keytab();

        keytab.setKeytabVersion( keytabVersion );
        keytab.setEntries( entries );

        return keytab;
    }


    /**
     * Returns the contents of the {@link java.io.File} in a byte array.
     *
     * @param file
     * @return The byte array of the file contents.
     * @throws java.io.IOException
     */
    protected static byte[] getBytesFromFile( File file ) throws IOException
    {
        InputStream is = new FileInputStream( file );

        long length = file.length();

        // Check to ensure that file is not larger than Integer.MAX_VALUE.
        if ( length > Integer.MAX_VALUE )
        {
            is.close();
            throw new IOException( I18n.err( I18n.ERR_618, file.getName() ) );
        }

        // Create the byte array to hold the data.
        byte[] bytes = new byte[( int ) length];

        // Read in the bytes
        int offset = 0;
        int numRead = 0;
        while ( offset < bytes.length && ( numRead = is.read( bytes, offset, bytes.length - offset ) ) >= 0 )
        {
            offset += numRead;
        }

        // Ensure all the bytes have been read in.
        if ( offset < bytes.length )
        {
            is.close();
            throw new IOException( I18n.err( I18n.ERR_619, file.getName() ) );
        }

        // Close the input stream and return bytes.
        is.close();

        return bytes;
    }


    /**
     * Write the contents of the {@link java.nio.ByteBuffer} to a {@link java.io.File}.
     *
     * @param buffer
     * @param file
     * @throws java.io.IOException
     */
    protected void writeFile( ByteBuffer buffer, File file ) throws IOException
    {
        // Set append false to replace existing.
        FileChannel wChannel = new FileOutputStream( file, false ).getChannel();

        // Write the bytes between the position and limit.
        wChannel.write( buffer );

        wChannel.close();
    }
}
