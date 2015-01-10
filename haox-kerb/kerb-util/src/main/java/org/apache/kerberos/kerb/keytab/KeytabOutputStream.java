package org.apache.kerberos.kerb.keytab;

import org.apache.kerberos.kerb.KrbOutputStream;
import org.apache.kerberos.kerb.spec.common.EncryptionKey;
import org.apache.kerberos.kerb.spec.common.PrincipalName;

import java.io.IOException;
import java.io.OutputStream;
import java.util.List;

public class KeytabOutputStream extends KrbOutputStream
{
	public KeytabOutputStream(OutputStream out) {
        super(out);
    }

    public void writePrincipal(PrincipalName principal, int version) throws IOException {
        List<String> nameStrings = principal.getNameStrings();
        int numComponents = principal.getNameStrings().size();
        String realm = principal.getRealm();

        writeShort(numComponents);

        writeCountedString(realm);

        for (String nameCom : nameStrings) {
            writeCountedString(nameCom);
        }

        writeInt(principal.getNameType().getValue()); // todo: consider the version
    }

    @Override
    public void writeKey(EncryptionKey key, int version) throws IOException {
    	writeShort(key.getKeyType().getValue());
        writeCountedOctets(key.getKeyData());
    }

    @Override
    public void writeCountedOctets(byte[] data) throws IOException {
        writeShort(data.length);
        write(data);
    }
}
