package org.haox.kerb.common.event;

public abstract class KrbEvent {

    public static enum EventType {
        NEW_TRANSPORT,
        WRITEABLE_TRANSPORT,
        READABLE_TRANSPORT,
        NEW_MESSAGE;
    }

    private EventType eventType;

    public KrbEvent(EventType eventType) {
        this.eventType = eventType;
    }

    public EventType getEventType() {
        return eventType;
    }
}
