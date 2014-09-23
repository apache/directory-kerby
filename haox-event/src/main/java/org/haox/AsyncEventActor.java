package org.haox;

public abstract class AsyncEventActor extends EventActor {

    private Thread thread;

    public AsyncEventActor() {
        super();
    }

    @Override
    protected void doStart() {
        init();
        thread = new Thread(new TheRunnable());
        thread.start();
    }

    protected void doStop() {
        if (thread != null) {
            thread.interrupt();
            try {
                thread.join();
            } catch (InterruptedException ie) {

            }
        }
    }

    /**
     * returns true to mean terminating the loop
     */
    protected boolean loopOnce() {
        try {
            return takeAndProcess();
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    class TheRunnable implements Runnable {
        @Override
        public void run() {
            while (!isStopped() && !Thread.currentThread().isInterrupted()) {
                try {
                    if (loopOnce()) break;
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }
}