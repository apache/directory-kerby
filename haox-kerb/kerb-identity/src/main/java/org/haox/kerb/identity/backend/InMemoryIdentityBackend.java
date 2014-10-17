package org.haox.kerb.identity.backend;

import org.haox.kerb.identity.KrbIdentity;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class InMemoryIdentityBackend extends AbstractIdentityBackend {

    private Map<String, KrbIdentity> identities;

    public InMemoryIdentityBackend() {
        this.identities = new HashMap<String, KrbIdentity>();
    }

    public InMemoryIdentityBackend(Map<String, KrbIdentity> identities) {
        this();
        this.identities.putAll(identities);
    }

    @Override
    public List<KrbIdentity> getIdentities() {
        List<KrbIdentity> results = new ArrayList<KrbIdentity>(identities.size());
        results.addAll(identities.values());
        return results;
    }

    @Override
    public boolean checkIdentity(String name) {
        return identities.containsKey(name);
    }

    @Override
    public KrbIdentity getIdentity(String name) {
        if (identities.containsKey(name)) {
            return identities.get(name);
        }
        return null;
    }

    @Override
    public void addIdentity(KrbIdentity identity) {
        identities.put(identity.getPrincipalName(), identity);
    }

    @Override
    public void updateIdentity(KrbIdentity identity) {
        identities.put(identity.getPrincipalName(), identity);
    }

    @Override
    public void deleteIdentity(KrbIdentity identity) {
        identities.remove(identity.getPrincipalName());
    }
}
