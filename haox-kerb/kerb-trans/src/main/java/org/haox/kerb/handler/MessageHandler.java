package org.haox.kerb.handler;

import org.haox.kerb.event.MessageEvent;

public interface MessageHandler extends Handler {

    public void handleMessage(MessageEvent event);

}
