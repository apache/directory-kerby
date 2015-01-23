/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.kerby.event;

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
        Future<Event> future = doWaitEvent(eventType);

        try {
            return future.get();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } catch (ExecutionException e) {
            throw new RuntimeException(e);
        }
    }

    public Event waitEvent(final EventType eventType,
                           long timeout, TimeUnit timeUnit) throws TimeoutException {
        Future<Event> future = doWaitEvent(eventType);

        try {
            return future.get(timeout, timeUnit);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } catch (ExecutionException e) {
            throw new RuntimeException(e);
        }
    }

    public Event waitEvent(long timeout, TimeUnit timeUnit) throws TimeoutException {
        Future<Event> future = doWaitEvent(null);

        try {
            return future.get(timeout, timeUnit);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } catch (ExecutionException e) {
            throw new RuntimeException(e);
        }
    }

    private Future<Event> doWaitEvent(final EventType eventType) {
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

        return future;
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