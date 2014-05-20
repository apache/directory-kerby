package org.haox.kerb.handler;

import org.haox.kerb.Actor;
import org.haox.kerb.event.Event;
import org.haox.kerb.event.EventType;
import org.haox.kerb.event.TransportEvent;
import org.haox.kerb.transport.Transport;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class AbstractTransportHandler extends Actor implements TransportHandler {

    private final BlockingQueue<TransportEvent> eventQueue;

    public AbstractTransportHandler() {
        super();
        this.eventQueue = new LinkedBlockingQueue<TransportEvent>();
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
    public void handleTransport(TransportEvent event) {
        eventQueue.add(event);
    }

    @Override
    public void handle(Event event) {
        if (! (event instanceof TransportEvent)) {
            throw new RuntimeException("Message dispatcher met non-transport event");
        }

        handleTransport((TransportEvent) event);
    }

    protected void process(TransportEvent event) {
        Transport transport = event.getTransport();

        EventType eventType = event.getEventType();
        switch (eventType) {
            case NEW_TRANSPORT:
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

    @Override
    protected boolean loopOnce() {
        TransportEvent event;
        try {
            event = eventQueue.take();
        } catch(InterruptedException ie) {
            if (!isStopped()) {
                //LOG.warn("AsyncDispatcher thread interrupted", ie);
            }
            return true;
        }
        if (event != null) {
            process(event);
        }

        return false;
    }
}

