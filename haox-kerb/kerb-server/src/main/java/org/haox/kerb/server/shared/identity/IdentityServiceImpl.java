package org.haox.kerb.server.shared.identity;

import org.haox.kerb.server.shared.identity.IdentityEntry;
import org.haox.kerb.server.shared.identity.IdentityService;

/**
 * A IdentityService backing entries in a DirectoryService.
 */
public class IdentityServiceImpl implements IdentityService
{
    public IdentityEntry getIdentity(String principal) throws Exception {
        IdentityEntry entry = new IdentityEntry();

        return entry;
    }
}
