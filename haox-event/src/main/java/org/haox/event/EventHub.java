package org.haox.event;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class EventHub implements Dispatcher {

    private enum BuiltInEventType implements EventType {
        START,
        STOP,
        TERMINATE
    }

    private Map<Integer, InternalEventHandler> handlers =
            new ConcurrentHashMap<Integer, InternalEventHandler>();

    private Map<EventType, Set<Integer>> eventHandlersMap =
        new ConcurrentHashMap<EventType, Set<Integer>>();

    class HubEventHandler extends AbstractEventHandler {

        public HubEventHandler(Dispatcher dispatcher) {
            super(dispatcher);
        }

        @Override
        protected void doHandle(Event event) {

        }

        @Override
        public EventType[] getInterestedEvents() {
            return new EventType[] {
                    BuiltInEventType.STOP
            };
        }
    }

    public EventHub() {
        EventHandler eh = new HubEventHandler(this);
        InternalEventHandler ieh = new ExecutedEventHandler(eh);
        register(ieh);
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

    private void process(Event event) {
        EventType eventType = event.getEventType();

        Set<Integer> handlerIds = eventHandlersMap.get(eventType);
        InternalEventHandler handler;
        for (Integer hid : handlerIds) {
            handler = handlers.get(hid);
            handler.handle(event);
        }
    }

    public void start() {
        for (InternalEventHandler handler : handlers.values()) {
            handler.start();
        }
    }

    public void stop() {
        dispatch(new Event(BuiltInEventType.STOP));
    }
}
