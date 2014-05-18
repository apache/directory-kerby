package org.haox.kerb.common.handler;

import org.haox.kerb.common.event.MessageEvent;

public interface MessageHandler extends KrbHandler {

    public void handleMessage(MessageEvent event);

}
