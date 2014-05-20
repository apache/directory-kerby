package org.haox.kerb.dispatch;

import org.haox.kerb.Actor;
import org.haox.kerb.event.Event;
import org.haox.kerb.event.EventType;
import org.haox.kerb.handler.Handler;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;

public class AsyncDispatcher extends Actor implements Dispatcher {

    private ConcurrentHashMap<EventType, Handler> handlers;
    private final BlockingQueue<Event> eventQueue;

    public AsyncDispatcher() {
        super();
        this.handlers = new ConcurrentHashMap<EventType, Handler>();
        this.eventQueue = new LinkedBlockingQueue<Event>();

        /*
        KrbMessageDispatcher krbDispatcher = new KrbMessageDispatcher();
        MessageHandler msgHandler = new SimpleMessageHandler();
        register(krbDispatcher);
        register(msgHandler);
        */
    }

    @Override
    public void dispatch(Event event) {
        eventQueue.add(event);
    }

    @Override
    public void register(Handler handler) {
        for (EventType et : handler.getInterestedEvents()) {
            handlers.put(et, handler);
        }
    }

    protected void process(Event event) {
        EventType eventType = event.getEventType();
        Handler handler = handlers.get(eventType);
        if (handler != null) {
            handler.handle(event);
        }
    }

    @Override
    protected boolean loopOnce() {
        Event event;
        try {
            event = eventQueue.take();
        } catch(InterruptedException ie) {
            if (!isStopped()) {
                //LOG.warn("AsyncDispatcher thread interrupted", ie);
            }
            return true;
        }
        if (event != null) {
            process(event);
        }

        return false;
    }
}
