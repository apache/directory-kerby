package org.haox.kerb;

import org.haox.kerb.spec.common.KrbError;

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
