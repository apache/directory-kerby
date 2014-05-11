package org.haox.kerb.spec;

import org.haox.kerb.spec.type.common.KrbError;

public class KrbErrorException extends KrbException {
    private KrbError krbError;

    public KrbErrorException(KrbError krbError) {
        super(krbError.getErrorCode().getMessage());
        this.krbError = krbError;
    }

    public KrbError getKrbError() {
        return krbError;
    }
}
