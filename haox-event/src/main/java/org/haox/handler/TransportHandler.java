package org.haox.handler;

import org.haox.event.Event;
import org.haox.event.EventType;
import org.haox.event.TransportEvent;
import org.haox.transport.Transport;

public abstract class TransportHandler extends SyncEventHandler {

    public TransportHandler() {
        super();
    }

    @Override
    public EventType[] getInterestedEvents() {
        return new EventType[] {
                EventType.NEW_TRANSPORT,
                EventType.READABLE_TRANSPORT,
                EventType.WRITEABLE_TRANSPORT
        };
    }

    @Override
    public void process(Event event) {
        TransportEvent te = (TransportEvent) event;
        Transport transport = te.getTransport();

        EventType eventType = event.getEventType();
        switch (eventType) {
            case NEW_TRANSPORT:
                onNewTransport(((TransportEvent) event).getTransport());
                break;
            case READABLE_TRANSPORT:
                transport.onReadable();
                break;
            case WRITEABLE_TRANSPORT:
                transport.onWriteable();
                break;
            default:
                break;
        }
    }

    protected abstract void onNewTransport(Transport transport);
}

