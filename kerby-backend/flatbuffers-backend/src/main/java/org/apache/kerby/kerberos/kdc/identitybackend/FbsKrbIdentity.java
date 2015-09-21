// automatically generated, do not modify

package org.apache.kerby.kerberos.kdc.identitybackend;

import java.nio.*;
import java.lang.*;
import java.util.*;
import com.google.flatbuffers.*;

@SuppressWarnings("unused")
public final class FbsKrbIdentity extends Table {
  public static FbsKrbIdentity getRootAsFbsKrbIdentity(ByteBuffer _bb) { return getRootAsFbsKrbIdentity(_bb, new FbsKrbIdentity()); }
  public static FbsKrbIdentity getRootAsFbsKrbIdentity(ByteBuffer _bb, FbsKrbIdentity obj) { _bb.order(ByteOrder.LITTLE_ENDIAN); return (obj.__init(_bb.getInt(_bb.position()) + _bb.position(), _bb)); }
  public FbsKrbIdentity __init(int _i, ByteBuffer _bb) { bb_pos = _i; bb = _bb; return this; }

  public FbsPrincipalName principal() { return principal(new FbsPrincipalName()); }
  public FbsPrincipalName principal(FbsPrincipalName obj) { int o = __offset(4); return o != 0 ? obj.__init(__indirect(o + bb_pos), bb) : null; }
  public int keyVersion() { int o = __offset(6); return o != 0 ? bb.getInt(o + bb_pos) : 0; }
  public boolean mutateKeyVersion(int keyVersion) { int o = __offset(6); if (o != 0) { bb.putInt(o + bb_pos, keyVersion); return true; } else { return false; } }
  public int kdcFlags() { int o = __offset(8); return o != 0 ? bb.getInt(o + bb_pos) : 0; }
  public boolean mutateKdcFlags(int kdcFlags) { int o = __offset(8); if (o != 0) { bb.putInt(o + bb_pos, kdcFlags); return true; } else { return false; } }
  public boolean disabled() { int o = __offset(10); return o != 0 ? 0!=bb.get(o + bb_pos) : false; }
  public boolean mutateDisabled(boolean disabled) { int o = __offset(10); if (o != 0) { bb.put(o + bb_pos, (byte)(disabled ? 1 : 0)); return true; } else { return false; } }
  public FbsEncryptionKey keys(int j) { return keys(new FbsEncryptionKey(), j); }
  public FbsEncryptionKey keys(FbsEncryptionKey obj, int j) { int o = __offset(12); return o != 0 ? obj.__init(__indirect(__vector(o) + j * 4), bb) : null; }
  public int keysLength() { int o = __offset(12); return o != 0 ? __vector_len(o) : 0; }

  public static int createFbsKrbIdentity(FlatBufferBuilder builder,
      int principal,
      int keyVersion,
      int kdcFlags,
      boolean disabled,
      int keys) {
    builder.startObject(5);
    FbsKrbIdentity.addKeys(builder, keys);
    FbsKrbIdentity.addKdcFlags(builder, kdcFlags);
    FbsKrbIdentity.addKeyVersion(builder, keyVersion);
    FbsKrbIdentity.addPrincipal(builder, principal);
    FbsKrbIdentity.addDisabled(builder, disabled);
    return FbsKrbIdentity.endFbsKrbIdentity(builder);
  }

  public static void startFbsKrbIdentity(FlatBufferBuilder builder) { builder.startObject(5); }
  public static void addPrincipal(FlatBufferBuilder builder, int principalOffset) { builder.addOffset(0, principalOffset, 0); }
  public static void addKeyVersion(FlatBufferBuilder builder, int keyVersion) { builder.addInt(1, keyVersion, 0); }
  public static void addKdcFlags(FlatBufferBuilder builder, int kdcFlags) { builder.addInt(2, kdcFlags, 0); }
  public static void addDisabled(FlatBufferBuilder builder, boolean disabled) { builder.addBoolean(3, disabled, false); }
  public static void addKeys(FlatBufferBuilder builder, int keysOffset) { builder.addOffset(4, keysOffset, 0); }
  public static int createKeysVector(FlatBufferBuilder builder, int[] data) { builder.startVector(4, data.length, 4); for (int i = data.length - 1; i >= 0; i--) builder.addOffset(data[i]); return builder.endVector(); }
  public static void startKeysVector(FlatBufferBuilder builder, int numElems) { builder.startVector(4, numElems, 4); }
  public static int endFbsKrbIdentity(FlatBufferBuilder builder) {
    int o = builder.endObject();
    return o;
  }
};

