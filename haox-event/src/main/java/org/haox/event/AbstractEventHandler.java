package org.haox.event;

public abstract class AbstractEventHandler implements EventHandler {

    private Dispatcher dispatcher;

    public AbstractEventHandler(Dispatcher dispatcher) {
        this.dispatcher = dispatcher;
    }

    protected void dispatch(Event event) {
        dispatcher.dispatch(event);
    }

    public Dispatcher getDispatcher() {
        return dispatcher;
    }

    public void handle(Event event) {
        try {
            doHandle(event);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    protected abstract void doHandle(Event event) throws Exception;
}

