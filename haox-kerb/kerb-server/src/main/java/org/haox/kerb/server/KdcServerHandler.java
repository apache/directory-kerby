package org.haox.kerb.server;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.kdc.AsRep;
import org.haox.kerb.spec.type.kdc.AsReq;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KdcServerHandler extends SimpleChannelInboundHandler<Object> {
    private static final Logger logger = LoggerFactory.getLogger(KdcServerHandler.class);

    @Override
    public void messageReceived(ChannelHandlerContext ctx, Object msg) throws Exception {
        logger.info("message received, msg:" + msg.toString());

        ByteBuf byteBuf = (ByteBuf) msg;
        int len = byteBuf.readInt();
        byte[] buffer = new byte[len];
        byteBuf.readBytes(buffer);
        /*
        ByteBuffer byteBuffer = null;
        if (byteBuf.hasArray()) {
            buffer = byteBuf.array();
        } else if (byteBuf.nioBufferCount() > 0) {
            byteBuffer = byteBuf.nioBuffer();
        } else {
            byteBuffer = ByteBuffer.allocate(byteBuf.capacity());
            byteBuf.readBytes(byteBuffer);
        }
        if (byteBuffer != null) {
            if (byteBuffer.hasArray()) {
                buffer = byteBuffer.array();
            } else {
                buffer = new byte[byteBuffer.remaining()];
                byteBuffer.get(buffer);
            }
        } */

        AsReq asReq = null;
        try {
            asReq = KrbCodec.decode(buffer, AsReq.class);
        } catch (KrbException e) {
            e.printStackTrace();
        }

        AsRep asRep = null;
        try {
            asRep = processAsReq(asReq);
        } catch (KrbException e) {
            e.printStackTrace();
        }

        ctx.channel().writeAndFlush(msg);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx,
            Throwable cause) throws Exception {
        // Close the connection when an exception is raised.
        logger.warn("Unexpected exception from downstream.", cause);
        ctx.close();
    }

    private AsRep processAsReq(AsReq asReq) throws KrbException {
        AsRep asRep = new AsRep();

        asRep.setCname(asReq.getReqBody().getCname());
        asRep.setCrealm(asReq.getReqBody().getRealm());

        return asRep;
    }
}
