package org.haox.event;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public abstract class LongRunningEventHandler extends BufferedEventHandler {

    private ExecutorService executorService;

    public LongRunningEventHandler(EventHandler handler) {
        super(handler);
    }

    public LongRunningEventHandler(Dispatcher dispatcher) {
        super(dispatcher);
    }

    protected abstract void loopOnce();

    @Override
    public void start() {
        executorService = Executors.newFixedThreadPool(1);
        executorService.execute(new Runnable() {
            @Override
            public void run() {
                while (true) {

                    processEvents();

                    loopOnce();

                    try {
                        Thread.sleep(10);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            }
        });
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

    protected void processEvents() {
        while (! eventQueue.isEmpty()) {
            try {
                process(eventQueue.take());
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }
    }
}