package org.haox.kerb.spec.type.common;

import java.util.List;

public class AuthorizationData {
    private List<AuthorizationDataEntry> entries;

    public List<AuthorizationDataEntry> getEntries() {
        return entries;
    }

    public void setEntries(List<AuthorizationDataEntry> entries) {
        this.entries = entries;
    }
}
