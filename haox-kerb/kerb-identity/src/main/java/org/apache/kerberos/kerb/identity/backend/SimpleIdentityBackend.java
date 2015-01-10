package org.apache.kerberos.kerb.identity.backend;

import java.io.File;

public class SimpleIdentityBackend extends InMemoryIdentityBackend {

    private File identityFile;

    public SimpleIdentityBackend(File identityFile) {
        super();
        this.identityFile = identityFile;
    }

    /**
     * Load identities from file
     */
    public void load() {
        // todo
    }

    /**
     * Persist the updated identities back
     */
    public void save() {
        // todo
    }
}
