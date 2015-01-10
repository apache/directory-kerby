package org.apache.haox.event;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public interface EventWaiter {

    public abstract Event waitEvent(EventType event);

    public abstract Event waitEvent();

    public abstract Event waitEvent(EventType event, long timeout, TimeUnit timeUnit) throws TimeoutException;

    public abstract Event waitEvent(long timeout, TimeUnit timeUnit) throws TimeoutException;

}
