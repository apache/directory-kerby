package org.haox.kerb.handler;

import org.haox.kerb.event.Event;
import org.haox.kerb.event.EventType;

public interface Handler {

    public void handle(Event event);

    public EventType[] getInterestedEvents();
}
