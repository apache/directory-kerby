package org.haox.kerb.handler;

import org.haox.kerb.EventActor;
import org.haox.kerb.event.Event;

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

