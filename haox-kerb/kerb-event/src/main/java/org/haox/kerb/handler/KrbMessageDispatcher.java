package org.haox.kerb.handler;

import org.haox.kerb.event.Event;
import org.haox.kerb.event.EventType;
import org.haox.kerb.event.KrbMessageEvent;
import org.haox.kerb.spec.type.common.KrbMessage;
import org.haox.kerb.spec.type.common.KrbMessageType;

import java.util.concurrent.ConcurrentHashMap;

public class KrbMessageDispatcher implements Handler {

    private ConcurrentHashMap<KrbMessageType, KrbMessageHandler> handlers;

    public KrbMessageDispatcher() {
        this.handlers = new ConcurrentHashMap<KrbMessageType, KrbMessageHandler>();
    }

    public void register(KrbMessageType messageType, KrbMessageHandler handler) {
        handlers.put(messageType, handler);
    }

    @Override
    public EventType[] getInterestedEvents() {
        return new EventType[] {
                EventType.NEW_INBOUND_KRBMESSAGE
        };
    }

    @Override
    public void handle(Event event) {
        if (! (event instanceof KrbMessageEvent)) {
            throw new RuntimeException("Message dispatcher met non-message event");
        }
        KrbMessageEvent me = (KrbMessageEvent) event;
        KrbMessage message = me.getMessage();
        KrbMessageHandler handler = handlers.get(message.getMsgType());
        handler.handleMessage(me);
    }
}
