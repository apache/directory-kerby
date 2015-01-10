package org.apache.haox.event;

public class Event {

    private EventType eventType;
    private Object eventData;

    public Event(EventType eventType) {
        this.eventType = eventType;
    }

    public Event(EventType eventType, Object eventData) {
        this.eventType = eventType;
        this.eventData = eventData;
    }

    public EventType getEventType() {
        return eventType;
    }

    public Object getEventData() {
        return eventData;
    }
}
