package org.haox.kerb.handler;

import org.haox.kerb.AsyncEventActor;
import org.haox.kerb.event.Event;

public abstract class AsyncEventHandler extends AsyncEventActor implements EventHandler {

    public AsyncEventHandler() {
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

