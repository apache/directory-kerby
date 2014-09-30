package org.haox.event;

import java.util.concurrent.*;

public class WaitEventHandler extends BufferedEventHandler {

    private ExecutorService executorService;

    public WaitEventHandler(EventHandler handler) {
        super(handler);
    }

    public Event waitEvent(final EventType eventType) {
        Future<Event> future = executorService.submit(new Callable<Event>() {
            @Override
            public Event call() throws Exception {
                Event result = check(eventType);
                return result;
            }
        });

        Event result = null;
        try {
            result = future.get();
        } catch (InterruptedException e) {
            return null;
        } catch (ExecutionException e) {
            return null;
        }

        return result;
    }

    private Event check(EventType eventType) throws Exception {
        Event event = null;

        while (true) {
            event = eventQueue.take();
            if (event.getEventType() == eventType) {
                break;
            }
        }
        return event;
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