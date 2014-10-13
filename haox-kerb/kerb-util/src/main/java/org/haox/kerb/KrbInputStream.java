package org.haox.kerb;

import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.common.PrincipalName;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;

public abstract class KrbInputStream extends DataInputStream
{
    public KrbInputStream(InputStream in) {
        super(in);
    }

    public KerberosTime readTime() throws IOException {
        long value = readInt();
        KerberosTime time = new KerberosTime(value * 1000);
        return time;
    }

    public abstract PrincipalName readPrincipal(int version) throws IOException;

    public EncryptionKey readKey(int version) throws IOException {
        int eType = readShort();
        EncryptionType encryptionType = EncryptionType.fromValue(eType);

        byte[] keyData = readCountedOctets();
        EncryptionKey key = new EncryptionKey(encryptionType, keyData);

        return key;
    }

    public String readCountedString() throws IOException {
        byte[] countedOctets = readCountedOctets();
        // ASCII
        return new String(countedOctets);
    }

    public byte[] readCountedOctets() throws IOException {
        int len = readOctetsCount();
        if (len == 0) {
            return null;
        }

        byte[] data = new byte[len];
        read(data);

        return data;
    }

    public abstract int readOctetsCount() throws IOException;
}
