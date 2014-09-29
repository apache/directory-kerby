package org.haox.transport;

import org.haox.event.AbstractEventHandler;
import org.haox.event.Dispatcher;
import org.haox.event.Event;
import org.haox.event.EventType;
import org.haox.transport.event.TransportEvent;
import org.haox.transport.event.TransportEventType;

public abstract class TransportHandler extends AbstractEventHandler {

    public TransportHandler(Dispatcher dispatcher) {
        super(dispatcher);
    }

    @Override
    public EventType[] getInterestedEvents() {
        return new TransportEventType[] {
                TransportEventType.NEW_TRANSPORT,
                TransportEventType.READABLE_TRANSPORT,
                TransportEventType.WRITEABLE_TRANSPORT
        };
    }

    @Override
    protected void doHandle(Event event) throws Exception {
        TransportEvent te = (TransportEvent) event;
        Transport transport = te.getTransport();

        EventType eventType = event.getEventType();
        if (eventType == TransportEventType.NEW_TRANSPORT) {
            onNewTransport(((TransportEvent) event).getTransport());
        } else if (eventType == TransportEventType.READABLE_TRANSPORT) {
            transport.onReadable();
        } else if (eventType == TransportEventType.WRITEABLE_TRANSPORT) {
            transport.onWriteable();
        }
    }

    protected abstract void onNewTransport(Transport transport);
}

