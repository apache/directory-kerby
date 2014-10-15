package org.haox.kerb.identity;

import java.util.List;

public interface IdentityService {
    public List<Identity> getIdentities();
    public boolean checkIdentity(String name);
    public Identity getIdentity(String name);
    public void addIdentity(Identity identity);
    public void updateIdentity(Identity identity);
    public void deleteIdentity(Identity identity);
}
