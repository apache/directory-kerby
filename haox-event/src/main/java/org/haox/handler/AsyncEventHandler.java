package org.haox.handler;

import org.haox.AsyncEventActor;
import org.haox.event.Event;

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

