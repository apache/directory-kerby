package org.haox.kerb.server.identity;

import java.io.File;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SimpleIdentityBackend extends AbstractIdentityBackend {
    private File identityFile;
    private Map<String, Identity> identities;
    private boolean loaded = false;

    public SimpleIdentityBackend(File identityFile) {
        this.identityFile = identityFile;
        this.identities = new HashMap<String, Identity>();
    }

    @Override
    public List<Identity> getIdentities() {
        checkAndload();
        return null;
    }

    @Override
    public boolean checkIdentity(String name) {
        checkAndload();
        return false;
    }

    @Override
    public Identity getIdentity(String name) {
        checkAndload();
        return null;
    }

    @Override
    public void addIdentity(Identity identity) {
        checkAndload();
    }

    @Override
    public void updateIdentity(Identity identity) {
        checkAndload();
    }

    @Override
    public void deleteIdentity(Identity identity) {
        checkAndload();
    }

    private void load() {

    }

    private void checkAndload() {
        if (! loaded) {
            load();
        }
    }

    private void save() {

    }
}
