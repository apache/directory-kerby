package org.haox.kerb.server;

import org.haox.kerb.identity.backend.SimpleIdentityBackend;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

public class SimpleKdcServer extends AbstractKdcServer {
    private static final Logger logger = LoggerFactory.getLogger(SimpleKdcServer.class);

    public SimpleKdcServer() {
        super();
    }

    @Override
    protected void initIdentityService() {
        File identityFile = new File(workDir, "simplekdb.dat");
        this.identityService = new SimpleIdentityBackend(identityFile);
    }
}