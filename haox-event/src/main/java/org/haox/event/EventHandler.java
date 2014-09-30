package org.haox.event;

public interface EventHandler {

    public void handle(Event event);

    public EventType[] getInterestedEvents();

    public Dispatcher getDispatcher();

    public void setDispatcher(Dispatcher dispatcher);
}
