package org.haox.kerb.spec.common;

import java.util.Map;

public interface KrbTokenEncoder {

    public byte[] encode(KrbToken token);
    public Map<String, Object> decode(KrbToken token);
}
