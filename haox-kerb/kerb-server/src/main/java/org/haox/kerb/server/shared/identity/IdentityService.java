package org.haox.kerb.server.shared.identity;


public interface IdentityService
{
    IdentityEntry getIdentity(String principal) throws Exception;
}
