package org.haox.event;

public interface EventWaiter {

    public abstract Event waitEvent(EventType event);

    public abstract Event waitEvent();

}
