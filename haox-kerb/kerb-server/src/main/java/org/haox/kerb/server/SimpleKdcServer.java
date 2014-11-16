package org.haox.kerb.server;

import org.haox.kerb.identity.IdentityService;
import org.haox.kerb.identity.backend.SimpleIdentityBackend;

import java.io.File;

public class SimpleKdcServer extends KdcServer {

    public SimpleKdcServer() {
        super();
    }

    public void init() {
        super.init();
        initIdentityService();
    }

    protected void initIdentityService() {
        File identityFile = new File(workDir, "simplekdb.dat");
        IdentityService identityService = new SimpleIdentityBackend(identityFile);
        setIdentityService(identityService);
    }
}