package org.haox.event;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * An EventHandler wrapper processing events using an ExecutorService
 */
public class ExecutedEventHandler extends AbstractInternalEventHandler {

    private ExecutorService executorService;

    public ExecutedEventHandler(EventHandler handler) {
        super(handler);
    }

    @Override
    protected void doHandle(final Event event) throws Exception {
        executorService.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    process(event);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        });
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

    @Override
    public void init() {

    }
}