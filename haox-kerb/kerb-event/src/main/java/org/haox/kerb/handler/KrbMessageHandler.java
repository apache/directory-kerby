package org.haox.kerb.handler;

import org.haox.kerb.event.KrbMessageEvent;

public interface KrbMessageHandler {

    public void handleMessage(KrbMessageEvent event);

}
