package org.haox.event;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class EventHub implements Dispatcher {

    private enum BuiltInEventType implements EventType {
        STOP,
        ALL
    }

    private Map<Integer, InternalEventHandler> handlers =
            new ConcurrentHashMap<Integer, InternalEventHandler>();

    private Map<EventType, Set<Integer>> eventHandlersMap =
        new ConcurrentHashMap<EventType, Set<Integer>>();

    private Map<EventType, EventWaiter> eventWaiters =
            new ConcurrentHashMap<EventType, EventWaiter>();

    private InternalEventHandler builtInHandler;

    class BuiltInEventHandler extends AbstractEventHandler {
        public BuiltInEventHandler(Dispatcher dispatcher) {
            super(dispatcher);
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
        EventHandler eh = new BuiltInEventHandler(this);
        builtInHandler = new ExecutedEventHandler(eh);
        register(builtInHandler);
    }

    @Override
    public void dispatch(Event event) {
        process(event);
    }

    @Override
    public void register(EventHandler handler) {
        InternalEventHandler ieh = new ExecutedEventHandler(handler);
        register(ieh);
    }

    @Override
    public void register(InternalEventHandler handler) {
        handler.init();

        handlers.put(handler.id(), handler);

        EventType[] interestedEvents = handler.getInterestedEvents();
        Set<Integer> tmpHandlers;
        for (EventType eventType : interestedEvents) {
            if (handlers.containsKey(eventType)) {
                tmpHandlers = eventHandlersMap.get(eventType);
            } else {
                tmpHandlers = new HashSet<Integer>();
                eventHandlersMap.put(eventType, tmpHandlers);
            }
            tmpHandlers.add(handler.id());
        }
    }

    public EventWaiter waitEvent(final EventType event) {
        if (eventWaiters.containsKey(event)) {
            return eventWaiters.get(event);
        }

        EventHandler handler = new AbstractEventHandler(this) {
            @Override
            protected void doHandle(Event event) throws Exception {
                // no op;
            }

            @Override
            public EventType[] getInterestedEvents() {
                return new EventType[] { event };
            }
        };

        final WaitEventHandler waitEventHandler = new WaitEventHandler(handler);
        register(waitEventHandler);
        EventWaiter waiter = new EventWaiter() {
            @Override
            public Event waitEvent() {
                return waitEventHandler.waitEvent(event);
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
        for (InternalEventHandler handler : handlers.values()) {
            handler.start();
        }
    }

    public void stop() {
        for (InternalEventHandler handler : handlers.values()) {
            handler.stop();
        }
    }
}
