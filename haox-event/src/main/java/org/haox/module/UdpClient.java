package org.haox.module;

import org.haox.event.AbstractEventHandler;
import org.haox.event.EventHub;

public abstract class UdpClient extends AbstractEventHandler {

    private EventHub eventHub;

    public UdpClient() {
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
