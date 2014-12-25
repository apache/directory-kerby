package org.apache.kerberos.kdc.server;

import org.apache.kerberos.kdc.identitybackend.LdapIdentityBackend;
import org.apache.kerberos.kerb.identity.IdentityService;
import org.apache.kerberos.kerb.server.KdcServer;

public class ApacheKdcServer extends KdcServer {

    public ApacheKdcServer() {
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