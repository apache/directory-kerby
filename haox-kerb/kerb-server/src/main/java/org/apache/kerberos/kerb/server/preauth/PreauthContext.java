package org.apache.kerberos.kerb.server.preauth;

import java.util.ArrayList;
import java.util.List;

public class PreauthContext {
    private boolean preauthRequired = true;
    private List<PreauthHandle> handles = new ArrayList<PreauthHandle>(5);

    public PreauthContext() {

    }

    public boolean isPreauthRequired() {
        return preauthRequired;
    }

    public void setPreauthRequired(boolean preauthRequired) {
        this.preauthRequired = preauthRequired;
    }

    public List<PreauthHandle> getHandles() {
        return handles;
    }
}
