package org.haox.event;

import java.util.concurrent.*;

public class WaitEventHandler extends BufferedEventHandler {

    private ExecutorService executorService;

    public WaitEventHandler(EventHandler handler) {
        super(handler);
    }

    public Event waitEvent() {
        return waitEvent(null);
    }

    public Event waitEvent(final EventType eventType) {
        Future<Event> future = executorService.submit(new Callable<Event>() {
            @Override
            public Event call() throws Exception {
                if (eventType != null) {
                    return checkEvent(eventType);
                } else {
                    return checkEvent();
                }
            }
        });

        try {
            return future.get();
        } catch (Exception e) {
            return null;
        }
    }

    private Event checkEvent() throws Exception {
        return eventQueue.take();
    }

    private Event checkEvent(EventType eventType) throws Exception {
        Event event = null;

        while (true) {
            if (eventQueue.size() == 1) {
                if (eventQueue.peek().getEventType() == eventType) {
                    return eventQueue.take();
                }
            } else {
                event = eventQueue.take();
                if (event.getEventType() == eventType) {
                    return event;
                } else {
                    eventQueue.put(event); // put back since not wanted
                }
            }
        }
    }

    @Override
    public void start() {
        executorService = Executors.newFixedThreadPool(2);
    }

    @Override
    public void stop() {
        if (executorService.isShutdown()) {
            return;
        }
        executorService.shutdown();
    }

    @Override
    public boolean isStopped() {
        return executorService.isShutdown();
    }
}