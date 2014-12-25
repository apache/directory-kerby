package org.apache.haox.transport;

import org.apache.haox.event.AbstractEventHandler;
import org.apache.haox.event.Event;
import org.apache.haox.event.EventType;
import org.apache.haox.transport.event.MessageEvent;
import org.apache.haox.transport.event.TransportEventType;

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
