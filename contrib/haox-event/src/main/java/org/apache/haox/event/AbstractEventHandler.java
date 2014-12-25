package org.apache.haox.event;

public abstract class AbstractEventHandler implements EventHandler {

    private Dispatcher dispatcher;

    public AbstractEventHandler() {

    }

    protected void dispatch(Event event) {
        dispatcher.dispatch(event);
    }

    @Override
    public Dispatcher getDispatcher() {
        return dispatcher;
    }

    @Override
    public void setDispatcher(Dispatcher dispatcher) {
        this.dispatcher = dispatcher;
    }

    @Override
    public void handle(Event event) {
        try {
            doHandle(event);
        } catch (Exception e) {
            throw new RuntimeException(event.toString(), e);
        }
    }

    protected abstract void doHandle(Event event) throws Exception;
}

