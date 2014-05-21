package org.haox.kerb.handler;

import org.haox.kerb.dispatch.Dispatcher;
import org.haox.kerb.event.Event;
import org.haox.kerb.event.EventType;

public interface EventHandler {

    public void handle(Event event);

    public EventType[] getInterestedEvents();

    public void setDispatcher(Dispatcher dispatcher);

    public void start();

    public void stop();
}
