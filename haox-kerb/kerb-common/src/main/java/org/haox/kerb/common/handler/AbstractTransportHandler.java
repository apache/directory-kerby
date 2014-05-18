package org.haox.kerb.common.handler;

import org.haox.kerb.common.KrbRunnable;
import org.haox.kerb.common.event.KrbEvent;
import org.haox.kerb.common.event.TransportEvent;
import org.haox.kerb.common.transport.KrbTransport;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class AbstractTransportHandler extends KrbRunnable implements TransportHandler {

    private final BlockingQueue<TransportEvent> eventQueue;

    public AbstractTransportHandler() {
        super();
        this.eventQueue = new LinkedBlockingQueue<TransportEvent>();
    }

    @Override
    public void handleTransport(TransportEvent event) {
        eventQueue.add(event);
    }

    @Override
    public void handle(KrbEvent event) {
        if (! (event instanceof TransportEvent)) {
            throw new RuntimeException("Message dispatcher met non-transport event");
        }

        handleTransport((TransportEvent) event);
    }

    protected void process(TransportEvent event) {
        KrbTransport transport = event.getTransport();

        KrbEvent.EventType eventType = event.getEventType();
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

