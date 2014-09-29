package org.haox.transport;

import org.haox.event.Dispatcher;
import org.haox.event.EventHandler;
import org.haox.event.LongRunningEventHandler;
import org.haox.transport.event.NewTransportEvent;

import java.io.IOException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.Iterator;
import java.util.Set;

public abstract class AbstractSelector extends LongRunningEventHandler {

    protected Selector selector;

    public AbstractSelector(Dispatcher dispatcher) {
        super(dispatcher);
    }

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
        if (selector.selectNow() > 0) {
            Set<SelectionKey> selectionKeys = selector.selectedKeys();
            Iterator<SelectionKey> iterator = selectionKeys.iterator();
            while (iterator.hasNext()) {
                SelectionKey selectionKey = iterator.next();
                iterator.remove();
                dealKey(selectionKey);
            }
        }
    }

    protected abstract void dealKey(SelectionKey selectionKey) throws IOException;

    protected void onNewTransport(Transport transport) {
        transport.setDispatcher(getDispatcher());
        dispatch(new NewTransportEvent(transport));
    }
}
