package org.haox.transport;

import org.haox.event.AbstractEventHandler;
import org.haox.event.Event;
import org.haox.event.EventType;
import org.haox.transport.event.MessageEvent;
import org.haox.transport.event.TransportEventType;

public abstract class MessageHandler extends AbstractEventHandler {

    @Override
    protected void doHandle(Event event) throws Exception {
        handleMessage((MessageEvent) event);
    }

    protected abstract void handleMessage(MessageEvent event) throws Exception;

    @Override
    public EventType[] getInterestedEvents() {
        return new EventType[] { TransportEventType.INBOUND_MESSAGE };
    }

}
