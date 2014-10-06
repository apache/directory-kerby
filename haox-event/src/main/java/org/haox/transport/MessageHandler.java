package org.haox.transport;

import org.haox.event.AbstractEventHandler;
import org.haox.event.EventType;
import org.haox.transport.event.TransportEventType;

public abstract class MessageHandler extends AbstractEventHandler {

    @Override
    public EventType[] getInterestedEvents() {
        return new EventType[] { TransportEventType.INBOUND_MESSAGE };
    }

}
