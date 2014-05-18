package org.haox.kerb.common.handler;

import org.haox.kerb.common.event.KrbEvent;

public interface KrbHandler {

    public void handle(KrbEvent event);

}
