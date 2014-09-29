package org.haox.transport;

import org.haox.event.AbstractEventHandler;
import org.haox.event.Dispatcher;
import org.haox.transport.event.TransportEventType;

public abstract class MessageHandler extends AbstractEventHandler {

    public MessageHandler(Dispatcher dispatcher) {
        super(dispatcher);
    }

    @Override
    public TransportEventType[] getInterestedEvents() {
        return new TransportEventType[] {
                TransportEventType.INBOUND_MESSAGE
        };
    }
}
