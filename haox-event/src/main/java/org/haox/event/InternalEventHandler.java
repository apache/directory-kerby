package org.haox.event;

public interface InternalEventHandler extends EventHandler {

    public int id();

    public void init();

    public void start();

    public void stop();

    public boolean isStopped();
}

