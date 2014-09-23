package org.haox.kerb.dispatch;

import org.haox.kerb.AsyncEventActor;
import org.haox.kerb.event.Event;
import org.haox.kerb.event.EventType;
import org.haox.kerb.handler.EventHandler;

import java.util.concurrent.ConcurrentHashMap;

public class AsyncDispatcher extends AsyncEventActor implements Dispatcher {

    private ConcurrentHashMap<EventType, EventHandler> handlers;

    public AsyncDispatcher() {
        super();
        this.handlers = new ConcurrentHashMap<EventType, EventHandler>();
        setDispatcher(this);
    }

    @Override
    public void dispatch(Event event) {
        post(event);
    }

    @Override
    public void register(EventHandler handler) {
        doRegister(handler, true);
    }

    private void doRegister(EventHandler handler, boolean start) {
        handler.setDispatcher(this);

        if (start) {
            handler.start();
        }

        for (EventType et : handler.getInterestedEvents()) {
            handlers.put(et, handler);
        }
    }

    public void registerWithoutStart(EventHandler handler) {
        doRegister(handler, false);
    }

    @Override
    public void process(Event event) {
        EventType eventType = event.getEventType();
        EventHandler handler = handlers.get(eventType);
        if (handler != null) {
            handler.handle(event);
        }
    }
}
