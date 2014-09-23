package org.haox.handler;

import org.haox.event.Event;
import org.haox.event.EventType;

public class AsyncMessageHandler extends AsyncEventHandler {

    private MessageHandler innerHandler;

    public AsyncMessageHandler(MessageHandler actualHandler) {
        super();
        this.innerHandler = actualHandler;
    }

    @Override
    public EventType[] getInterestedEvents() {
        return innerHandler.getInterestedEvents();
    }

    @Override
    public void process(Event event) throws Exception {
        innerHandler.process(event);
    }
}
