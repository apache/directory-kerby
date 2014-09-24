package org.haox.handler;

import org.haox.event.Event;
import org.haox.event.EventType;

public class AsyncTransportHandler extends AsyncEventHandler {

    private TransportHandler innerHandler;

    public AsyncTransportHandler(TransportHandler actualHandler) {
        super();
        this.innerHandler = actualHandler;
    }

    @Override
    public EventType[] getInterestedEvents() {
        return innerHandler.getInterestedEvents();
    }

    @Override
    public void process(Event event) {
        innerHandler.process(event);
    }
}

