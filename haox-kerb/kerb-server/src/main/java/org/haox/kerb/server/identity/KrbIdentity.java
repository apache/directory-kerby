package org.haox.kerb.server.identity;

public class KrbIdentity extends Identity {

    public KrbIdentity(String principal, String password) {
        super(principal);
        addAttribute(KrbAttributes.PRINCIPAL, principal);
        addAttribute(KrbAttributes.PASSWORD, password);
    }

    public String getPrincipal() {
        return getName();
    }

    public String getPassword() {
        return getSimpleAttribute(KrbAttributes.PASSWORD);
    }
}
