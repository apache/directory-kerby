package org.haox.kerb;

import org.haox.kerb.dispatch.Dispatcher;
import org.haox.kerb.event.Event;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

public abstract class EventActor {

    private volatile boolean started = false;
    private volatile boolean stopped = true;

    private Dispatcher dispatcher;
    private final BlockingQueue<Event> eventQueue;

    public EventActor() {
        this.eventQueue = new LinkedBlockingQueue<Event>();
    }

    protected void init() {

    }

    public void setDispatcher(Dispatcher dispatcher) {
        this.dispatcher = dispatcher;
    }

    public void post(Event event) {
        eventQueue.add(event);
    }

    protected Dispatcher getDispatcher() {
        return dispatcher;
    }

    synchronized public void start() {
        if (! started) {
            doStart();
            started = true;
            stopped = false;
        }
    }

    protected void doStart() {
        init();

        while (isStopped()) {
            try {
                takeAndProcess();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    synchronized public void stop() {
        if (! stopped && started) {
            doStop();
            stopped = true;
        }
    }

    protected void doStop() {

    }

    public boolean isStopped() {
        return stopped;
    }

    /**
     * Wait forever, until take one event and then process
     */
    protected boolean takeAndProcess() throws Exception {
        Event event;
        try {
            event = eventQueue.take();
        } catch(InterruptedException ie) {
            return true;
        }
        if (event != null) {
            process(event);
        }
        return false;
    }

    /**
     * Check until timeout or get one event and then process if any got
     */
    protected boolean checkAndProcess() throws Exception {
        Event event;
        try {
            event = eventQueue.poll(50, TimeUnit.MILLISECONDS);
        } catch(InterruptedException ie) {
            return true;
        }
        if (event != null) {
            process(event);
        }

        return false;
    }

    public abstract void process(Event event) throws Exception;
}