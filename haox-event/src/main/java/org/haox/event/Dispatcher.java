package org.haox.event;

public interface Dispatcher {

    public void dispatch(Event event);

    public void register(EventHandler handler);

    public void register(InternalEventHandler internalHandler);
}
