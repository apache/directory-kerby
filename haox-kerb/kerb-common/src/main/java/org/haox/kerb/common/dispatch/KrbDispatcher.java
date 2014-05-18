package org.haox.kerb.common.dispatch;

import org.haox.kerb.common.event.KrbEvent;
import org.haox.kerb.common.handler.KrbHandler;

public interface KrbDispatcher {

    public void dispatch(KrbEvent event);

    public void register(KrbEvent.EventType eventType, KrbHandler handler);

}
