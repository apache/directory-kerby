package org.apache.haox.event;

import java.util.concurrent.atomic.AtomicInteger;

public abstract class AbstractInternalEventHandler extends AbstractEventHandler
        implements InternalEventHandler {

    private int id = -1;
    protected EventHandler handler;

    private static AtomicInteger idGen = new AtomicInteger(1);

    public AbstractInternalEventHandler() {
        super();

        this.id = idGen.getAndIncrement();

        init();
    }

    public AbstractInternalEventHandler(EventHandler handler) {
        this();

        this.handler = handler;
    }

    protected void setEventHandler(EventHandler handler) {
        this.handler = handler;
    }

    @Override
    public int id() {
        return id;
    }

    public abstract void init();

    protected void process(Event event) {
        handler.handle(event);
    }

    @Override
    public EventType[] getInterestedEvents() {
        return handler.getInterestedEvents();
    }
}

