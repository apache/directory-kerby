package org.haox.kerb.handler;

import org.haox.kerb.event.Event;
import org.haox.kerb.event.EventType;
import org.haox.kerb.event.MessageEvent;

public abstract class SimpleMessageHandler implements MessageHandler {

    @Override
    public EventType[] getInterestedEvents() {
        return new EventType[] {
                EventType.NEW_INBOUND_MESSAGE,
                EventType.NEW_OUTBOUND_MESSAGE
        };
    }

    @Override
    public abstract void handleMessage(MessageEvent event);

    @Override
    public void handle(Event event) {
        if (! (event instanceof MessageEvent)) {
            throw new RuntimeException("Message dispatcher met non-message event");
        }

        handleMessage((MessageEvent) event);
    }
}
