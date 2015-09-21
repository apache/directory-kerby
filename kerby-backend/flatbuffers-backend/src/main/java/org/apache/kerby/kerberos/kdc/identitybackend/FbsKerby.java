// automatically generated, do not modify

package org.apache.kerby.kerberos.kdc.identitybackend;

import java.nio.*;
import java.lang.*;
import java.util.*;
import com.google.flatbuffers.*;

@SuppressWarnings("unused")
public final class FbsKerby extends Table {
  public static FbsKerby getRootAsFbsKerby(ByteBuffer _bb) { return getRootAsFbsKerby(_bb, new FbsKerby()); }
  public static FbsKerby getRootAsFbsKerby(ByteBuffer _bb, FbsKerby obj) { _bb.order(ByteOrder.LITTLE_ENDIAN); return (obj.__init(_bb.getInt(_bb.position()) + _bb.position(), _bb)); }
  public FbsKerby __init(int _i, ByteBuffer _bb) { bb_pos = _i; bb = _bb; return this; }

  public String name() { int o = __offset(4); return o != 0 ? __string(o + bb_pos) : null; }
  public ByteBuffer nameAsByteBuffer() { return __vector_as_bytebuffer(4, 1); }
  public FbsKrbIdentity identities(int j) { return identities(new FbsKrbIdentity(), j); }
  public FbsKrbIdentity identities(FbsKrbIdentity obj, int j) { int o = __offset(6); return o != 0 ? obj.__init(__indirect(__vector(o) + j * 4), bb) : null; }
  public int identitiesLength() { int o = __offset(6); return o != 0 ? __vector_len(o) : 0; }

  public static int createFbsKerby(FlatBufferBuilder builder,
      int name,
      int identities) {
    builder.startObject(2);
    FbsKerby.addIdentities(builder, identities);
    FbsKerby.addName(builder, name);
    return FbsKerby.endFbsKerby(builder);
  }

  public static void startFbsKerby(FlatBufferBuilder builder) { builder.startObject(2); }
  public static void addName(FlatBufferBuilder builder, int nameOffset) { builder.addOffset(0, nameOffset, 0); }
  public static void addIdentities(FlatBufferBuilder builder, int identitiesOffset) { builder.addOffset(1, identitiesOffset, 0); }
  public static int createIdentitiesVector(FlatBufferBuilder builder, int[] data) { builder.startVector(4, data.length, 4); for (int i = data.length - 1; i >= 0; i--) builder.addOffset(data[i]); return builder.endVector(); }
  public static void startIdentitiesVector(FlatBufferBuilder builder, int numElems) { builder.startVector(4, numElems, 4); }
  public static int endFbsKerby(FlatBufferBuilder builder) {
    int o = builder.endObject();
    return o;
  }
  public static void finishFbsKerbyBuffer(FlatBufferBuilder builder, int offset) { builder.finish(offset); }
};

