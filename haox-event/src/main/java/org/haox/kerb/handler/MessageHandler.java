package org.haox.kerb.handler;

import org.haox.kerb.event.EventType;

public abstract class MessageHandler extends SyncEventHandler {

    @Override
    public EventType[] getInterestedEvents() {
        return new EventType[] {
                EventType.NEW_INBOUND_MESSAGE,
                EventType.NEW_OUTBOUND_MESSAGE
        };
    }
}
