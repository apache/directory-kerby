package org.haox.event;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

/**
 * An EventHandler wrapper buffering events and processing them later
 */
public abstract class BufferedEventHandler extends AbstractInternalEventHandler {

    protected BlockingQueue<Event> eventQueue;

    public BufferedEventHandler(EventHandler handler) {
        super(handler);
    }

    public BufferedEventHandler(Dispatcher dispatcher) {
        super(dispatcher);
    }

    @Override
    public void init() {
        this.eventQueue = new ArrayBlockingQueue<Event>(2);
    }

    @Override
    protected void doHandle(Event event) throws Exception {
        try {
            eventQueue.put(event);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}