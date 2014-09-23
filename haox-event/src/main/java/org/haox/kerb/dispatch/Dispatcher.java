package org.haox.kerb.dispatch;

import org.haox.kerb.event.Event;
import org.haox.kerb.handler.EventHandler;

public interface Dispatcher {

    public void dispatch(Event event);

    public void register(EventHandler handler);

    public void registerWithoutStart(EventHandler handler);
}
