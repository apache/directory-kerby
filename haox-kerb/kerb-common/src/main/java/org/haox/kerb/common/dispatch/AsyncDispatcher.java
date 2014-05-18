package org.haox.kerb.common.dispatch;

import org.haox.kerb.common.KrbRunnable;
import org.haox.kerb.common.event.KrbEvent;
import org.haox.kerb.common.handler.KrbHandler;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class AsyncDispatcher extends KrbRunnable implements KrbDispatcher {

    private Map<KrbEvent.EventType, KrbHandler> handlers;
    private final BlockingQueue<KrbEvent> eventQueue;

    public AsyncDispatcher() {
        super();
        this.handlers = new HashMap<KrbEvent.EventType, KrbHandler>();
        this.eventQueue = new LinkedBlockingQueue<KrbEvent>();

        MessageDispatcher msgDispatcher = new MessageDispatcher();
        register(KrbEvent.EventType.NEW_MESSAGE, msgDispatcher);
    }

    @Override
    public void dispatch(KrbEvent event) {
        eventQueue.add(event);
    }

    @Override
    synchronized public void register(KrbEvent.EventType eventType, KrbHandler handler) {
        handlers.put(eventType, handler);
    }

    protected void process(KrbEvent event) {
        KrbEvent.EventType eventType = event.getEventType();
        KrbHandler handler = handlers.get(eventType);
        handler.handle(event);
    }

    @Override
    protected boolean loopOnce() {
        KrbEvent event;
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
