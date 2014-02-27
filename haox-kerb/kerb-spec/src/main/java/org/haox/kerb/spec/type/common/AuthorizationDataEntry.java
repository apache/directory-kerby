package org.haox.kerb.spec.type.common;

public class AuthorizationDataEntry {
    private AuthorizationType authzType;
    private byte[] authzData;

    public AuthorizationType getAuthzType() {
        return authzType;
    }

    public void setAuthzType(AuthorizationType authzType) {
        this.authzType = authzType;
    }

    public byte[] getAuthzData() {
        return authzData;
    }

    public void setAuthzData(byte[] authzData) {
        this.authzData = authzData;
    }
}
