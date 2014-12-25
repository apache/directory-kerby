package org.apache.kerberos.kerb.keytab;

import org.apache.kerberos.kerb.spec.common.EncryptionKey;
import org.apache.kerberos.kerb.spec.common.EncryptionType;
import org.apache.kerberos.kerb.spec.common.PrincipalName;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

public interface KrbKeytab {

    public List<PrincipalName> getPrincipals();

    public void addKeytabEntries(List<KeytabEntry> entries);

    public void removeKeytabEntries(PrincipalName principal);

    public void removeKeytabEntry(KeytabEntry entry);

    public List<KeytabEntry> getKeytabEntries(PrincipalName principal);

    public EncryptionKey getKey(PrincipalName principal, EncryptionType keyType);

    public void load(File keytabFile) throws IOException;

    public void load(InputStream inputStream) throws IOException;

    void addEntry(KeytabEntry entry);

    public void store(File keytabFile) throws IOException;

    public void store(OutputStream outputStream) throws IOException;
}
