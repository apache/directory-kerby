package org.haox.handler;

import org.haox.EventActor;
import org.haox.event.Event;

public abstract class SyncEventHandler extends EventActor implements EventHandler {

    public SyncEventHandler() {
        super();
    }

    @Override
    protected void init() {
        super.init();
    }

    @Override
    public void handle(Event event) {
        post(event);
    }
}

