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

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class EventHub implements Dispatcher {

    private enum BuiltInEventType implements EventType {
        STOP,
        ALL
    }

    private boolean started = false;

    private Map<Integer, InternalEventHandler> handlers =
            new ConcurrentHashMap<Integer, InternalEventHandler>();

    private Map<EventType, Set<Integer>> eventHandlersMap =
        new ConcurrentHashMap<EventType, Set<Integer>>();

    private InternalEventHandler builtInHandler;

    class BuiltInEventHandler extends AbstractEventHandler {
        public BuiltInEventHandler() {
            super();
        }

        @Override
        protected void doHandle(Event event) {

        }

        @Override
        public EventType[] getInterestedEvents() {
            return BuiltInEventType.values();
        }
    }

    public EventHub() {
        init();
    }

    private void init() {
        EventHandler eh = new BuiltInEventHandler();
        builtInHandler = new ExecutedEventHandler(eh);
        register(builtInHandler);
    }

    @Override
    public void dispatch(Event event) {
        process(event);
    }

    @Override
    public void register(EventHandler handler) {
        handler.setDispatcher(this);
        InternalEventHandler ieh = new ExecutedEventHandler(handler);
        register(ieh);
    }

    @Override
    public void register(InternalEventHandler handler) {
        handler.setDispatcher(this);
        handler.init();
        handlers.put(handler.id(), handler);

        if (started) {
            handler.start();
        }

        EventType[] interestedEvents = handler.getInterestedEvents();
        Set<Integer> tmpHandlers;
        for (EventType eventType : interestedEvents) {
            if (eventHandlersMap.containsKey(eventType)) {
                tmpHandlers = eventHandlersMap.get(eventType);
            } else {
                tmpHandlers = new HashSet<Integer>();
                eventHandlersMap.put(eventType, tmpHandlers);
            }
            tmpHandlers.add(handler.id());
        }
    }

    public EventWaiter waitEvent(final EventType event) {
        return waitEvent(new EventType[] { event } );
    }

    public EventWaiter waitEvent(final EventType... events) {
        EventHandler handler = new AbstractEventHandler() {
            @Override
            protected void doHandle(Event event) throws Exception {
                // no op;
            }

            @Override
            public EventType[] getInterestedEvents() {
                return events;
            }
        };

        handler.setDispatcher(this);
        final WaitEventHandler waitEventHandler = new WaitEventHandler(handler);
        register(waitEventHandler);
        EventWaiter waiter = new EventWaiter() {
            @Override
            public Event waitEvent(EventType event) {
                return waitEventHandler.waitEvent(event);
            }

            @Override
            public Event waitEvent() {
                return waitEventHandler.waitEvent();
            }

            @Override
            public Event waitEvent(EventType event, long timeout,
                                   TimeUnit timeUnit) throws TimeoutException {
                return waitEventHandler.waitEvent(event, timeout, timeUnit);
            }

            @Override
            public Event waitEvent(long timeout, TimeUnit timeUnit) throws TimeoutException {
                return waitEventHandler.waitEvent(timeout, timeUnit);
            }
        };

        return waiter;
    }

    private void process(Event event) {
        EventType eventType = event.getEventType();
        InternalEventHandler handler;
        Set<Integer> handlerIds;

        if (eventHandlersMap.containsKey(eventType)) {
            handlerIds = eventHandlersMap.get(eventType);
            for (Integer hid : handlerIds) {
                handler = handlers.get(hid);
                handler.handle(event);
            }
        }

        if (eventHandlersMap.containsKey(BuiltInEventType.ALL)) {
            handlerIds = eventHandlersMap.get(BuiltInEventType.ALL);
            for (Integer hid : handlerIds) {
                handler = handlers.get(hid);
                handler.handle(event);
            }
        }
    }

    public void start() {
        if (!started) {
            for (InternalEventHandler handler : handlers.values()) {
                handler.start();
            }
            started = true;
        }
    }

    public void stop() {
        if (started) {
            for (InternalEventHandler handler : handlers.values()) {
                handler.stop();
            }
            started = false;
        }
    }
}
