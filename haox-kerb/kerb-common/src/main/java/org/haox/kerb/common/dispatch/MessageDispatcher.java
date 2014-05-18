package org.haox.kerb.common.dispatch;

import org.haox.kerb.common.event.KrbEvent;
import org.haox.kerb.common.event.MessageEvent;
import org.haox.kerb.common.handler.KrbHandler;
import org.haox.kerb.common.handler.MessageHandler;
import org.haox.kerb.spec.type.common.KrbMessage;
import org.haox.kerb.spec.type.common.KrbMessageType;

import java.util.HashMap;
import java.util.Map;

public class MessageDispatcher implements KrbHandler {

    private Map<KrbMessageType, MessageHandler> handlers;

    public MessageDispatcher() {
        this.handlers = new HashMap<KrbMessageType, MessageHandler>();
    }

    synchronized public void register(KrbMessageType messageType, MessageHandler handler) {
        handlers.put(messageType, handler);
    }

    @Override
    public void handle(KrbEvent event) {
        if (! (event instanceof MessageEvent)) {
            throw new RuntimeException("Message dispatcher met non-message event");
        }
        MessageEvent me = (MessageEvent) event;
        KrbMessage message = me.getMessage();
        MessageHandler handler = handlers.get(message.getMsgType());
        handler.handle(event);
    }
}
