package org.haox.kerb.ccache;

import org.haox.kerb.spec.common.PrincipalName;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

public interface KrbCredentialCache {

    public PrincipalName getPrimaryPrincipal();

    public void setPrimaryPrincipal(PrincipalName principal);

    public int getVersion();

    public void setVersion(int version);

    public List<Credential> getCredentials();

    public void addCredential(Credential credential);

    public void addCredentials(List<Credential> credentials);

    public void removeCredentials(List<Credential> credentials);

    public void removeCredential(Credential credential);

    public void load(File ccacheFile) throws IOException;

    public void load(InputStream inputStream) throws IOException;

    public void store(File ccacheFile) throws IOException;

    public void store(OutputStream outputStream) throws IOException;
}
