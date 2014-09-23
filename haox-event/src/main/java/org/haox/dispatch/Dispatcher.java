package org.haox.dispatch;

import org.haox.event.Event;
import org.haox.handler.EventHandler;

public interface Dispatcher {

    public void dispatch(Event event);

    public void register(EventHandler handler);

    public void registerWithoutStart(EventHandler handler);
}
