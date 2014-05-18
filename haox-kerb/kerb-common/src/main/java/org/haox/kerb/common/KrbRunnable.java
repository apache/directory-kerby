package org.haox.kerb.common;

public abstract class KrbRunnable {
    private volatile boolean stopped = false;

    private Thread thread;

    public KrbRunnable() {

    }

    public void init() {

    }

    public void start() {
        thread = new Thread(new TheRunnable());
        thread.start();
    }

    public void stop() {
        stopped = true;
        stopped = true;
        if (thread != null) {
            thread.interrupt();
            try {
                thread.join();
            } catch (InterruptedException ie) {

            }
        }
    }

    public boolean isStopped() {
        return stopped;
    }

    class TheRunnable implements Runnable {
        @Override
        public void run() {
            while (!stopped && !Thread.currentThread().isInterrupted()) {
                try {
                    if (loopOnce()) break;
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * returns true to mean terminating the loop
     */
    protected abstract boolean loopOnce() throws Exception;
}
