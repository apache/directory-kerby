package org.haox.module;

import org.haox.event.AbstractEventHandler;
import org.haox.event.EventHub;

public abstract class EventModule extends AbstractEventHandler {

    private EventHub eventHub;

    public EventModule() {
        eventHub = new EventHub();
        setDispatcher(eventHub);
        eventHub.register(this);
    }

    public void start() {
        eventHub.start();
    }

    public void stop() {
        eventHub.stop();
    }

}
