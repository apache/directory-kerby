package org.apache.kerberos.kerb.identity;

import java.util.List;

public interface IdentityService {
    public List<KrbIdentity> getIdentities();
    public boolean checkIdentity(String name);
    public KrbIdentity getIdentity(String name);
    public void addIdentity(KrbIdentity identity);
    public void updateIdentity(KrbIdentity identity);
    public void deleteIdentity(KrbIdentity identity);
}
