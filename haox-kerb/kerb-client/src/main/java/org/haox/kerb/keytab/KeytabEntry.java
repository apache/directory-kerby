package org.haox.kerb.keytab;

import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.common.EncryptionKey;

/**
 * An entry within a keytab file.
 */
public class KeytabEntry
{
    private String principalName;

    private long principalType;

    private KerberosTime timeStamp;

    private byte keyVersion;

    private EncryptionKey key;


    /**
     * Creates a new instance of Entry.
     *
     * @param principalName
     * @param principalType
     * @param timeStamp
     * @param keyVersion
     * @param key
     */
    public KeytabEntry( String principalName, long principalType, KerberosTime timeStamp, byte keyVersion,
        EncryptionKey key )
    {
        this.principalName = principalName;
        this.principalType = principalType;
        this.timeStamp = timeStamp;
        this.keyVersion = keyVersion;
        this.key = key;
    }


    /**
     * @return The key.
     */
    public EncryptionKey getKey()
    {
        return key;
    }


    /**
     * @return The keyVersion.
     */
    public byte getKeyVersion()
    {
        return keyVersion;
    }


    /**
     * @return The principalName.
     */
    public String getPrincipalName()
    {
        return principalName;
    }


    /**
     * @return The principalType.
     */
    public long getPrincipalType()
    {
        return principalType;
    }


    /**
     * @return The timeStamp.
     */
    public KerberosTime getTimeStamp()
    {
        return timeStamp;
    }
}
