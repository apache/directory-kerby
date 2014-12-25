package org.apache.kerberos.kerb.server;

import org.apache.kerberos.kerb.identity.IdentityService;
import org.apache.kerberos.kerb.identity.backend.SimpleIdentityBackend;

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