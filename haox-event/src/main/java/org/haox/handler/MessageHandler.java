package org.haox.handler;

import org.haox.event.EventType;

public abstract class MessageHandler extends SyncEventHandler {

    @Override
    public EventType[] getInterestedEvents() {
        return new EventType[] {
                EventType.NEW_INBOUND_MESSAGE,
                EventType.NEW_OUTBOUND_MESSAGE
        };
    }
}
