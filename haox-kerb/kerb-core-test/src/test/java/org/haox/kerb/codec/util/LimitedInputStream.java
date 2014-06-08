package org.haox.kerb.codec.util;

import java.io.InputStream;

abstract class LimitedInputStream
        extends InputStream
{
    protected final InputStream _in;
    private int _limit;

    LimitedInputStream(
            InputStream in,
            int limit)
    {
        this._in = in;
        this._limit = limit;
    }

    int getRemaining()
    {
        // TODO: maybe one day this can become more accurate
        return _limit;
    }
}
