package org.haox.handler;

import org.haox.dispatch.Dispatcher;
import org.haox.event.Event;
import org.haox.event.EventType;

public interface EventHandler {

    public void handle(Event event);

    public EventType[] getInterestedEvents();

    public void setDispatcher(Dispatcher dispatcher);

    public void start();

    public void stop();
}
