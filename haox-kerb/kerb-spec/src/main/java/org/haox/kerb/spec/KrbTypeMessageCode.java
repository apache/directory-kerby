package org.haox.kerb.spec;

import java.util.HashMap;
import java.util.Map;

public enum KrbTypeMessageCode implements KrbMessageCode {
    INVALID_KRB_TYPE,
    INVALID_KRB_IMPL,
    NO_IMPL_FOUND;

    @Override
    public String getCodeName() {
        return name();
    }

}
