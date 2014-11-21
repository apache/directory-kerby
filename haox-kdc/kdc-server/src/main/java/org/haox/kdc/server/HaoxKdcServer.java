package org.haox.kdc.server;

import org.haox.kdc.identitybackend.LdapIdentityBackend;
import org.haox.kerb.identity.IdentityService;
import org.haox.kerb.server.KdcServer;

public class HaoxKdcServer extends KdcServer {

    public HaoxKdcServer() {
        super();
    }

    public void init() {
        super.init();
        initIdentityService();
    }

    protected void initIdentityService() {
        IdentityService identityService = new LdapIdentityBackend();
        setIdentityService(identityService);
    }
}