package org.haox.transport;

import org.haox.event.LongRunningEventHandler;
import org.haox.transport.event.NewTransportEvent;

import java.io.IOException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.Iterator;
import java.util.Set;

public abstract class AbstractSelector extends LongRunningEventHandler {

    protected Selector selector;

    @Override
    public void init() {
        super.init();

        try {
            selector = Selector.open();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void loopOnce() {
        try {
            selectOnce();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    protected void selectOnce() throws IOException {
        if (selector.isOpen() && selector.select(10) > 0 && selector.isOpen()) {
            Set<SelectionKey> selectionKeys = selector.selectedKeys();
            Iterator<SelectionKey> iterator = selectionKeys.iterator();
            while (iterator.hasNext()) {
                SelectionKey selectionKey = iterator.next();
                dealKey(selectionKey);
                iterator.remove();
            }
        }
    }

    protected abstract void dealKey(SelectionKey selectionKey) throws IOException;

    protected void onNewTransport(Transport transport) {
        transport.setDispatcher(getDispatcher());
        dispatch(new NewTransportEvent(transport));
    }

    @Override
    public void stop() {
        super.stop();

        try {
            selector.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
