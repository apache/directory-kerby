package org.haox.kerb.codec.util;

import java.nio.ByteBuffer;

public class HaoxDERApplicationSpecific extends ByteBufferASN1Object
{
    private final boolean   isConstructed;
    private final int       tag;

    public HaoxDERApplicationSpecific(boolean isConstructed,
            int tag,ByteBuffer byteBuffer, int limit) {
        super(byteBuffer, limit);
        this.isConstructed = isConstructed;
        this.tag = tag;
    }

    public boolean isConstructed()
    {
        return isConstructed;
    }

    public int getApplicationTag()
    {
        return tag;
    }
}