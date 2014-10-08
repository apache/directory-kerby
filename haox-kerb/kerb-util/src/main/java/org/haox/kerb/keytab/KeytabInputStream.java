package org.haox.kerb.keytab;

import org.haox.kerb.KrbInputStream;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.common.NameType;
import org.haox.kerb.spec.type.common.PrincipalName;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class KeytabInputStream extends KrbInputStream
{
    public KeytabInputStream(InputStream in) {
        super(in);
    }

    public KerberosTime readTime() throws IOException {
        long value = readInt();
        KerberosTime time = new KerberosTime(value * 1000);
        return time;
    }

    @Override
    public PrincipalName readPrincipal(int version) throws IOException {
        int numComponents = readShort();
        if (version == Keytab.V501) {
            numComponents -= 1;
        }

        String realm = readCountedString();

        List<String> nameStrings = new ArrayList<String>();
        String component;
        for (int i = 0; i < numComponents; i++) { // sub 1 if version 0x501
            component = readCountedString();
            nameStrings.add(component);
        }
        int type = readInt(); // not present if version 0x501
        NameType nameType = NameType.fromValue(type);
        PrincipalName principal = new PrincipalName(nameStrings, nameType);
        principal.setRealm(realm);

        return principal;
    }

    public EncryptionKey readKey() throws IOException {
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

    @Override
    public int readOctetsCount() throws IOException {
        return readShort();
    }
}
