package org.hyperledger.besu.nativelib;


import com.sun.jna.ptr.PointerByReference;
import java.io.IOException;
import java.util.Arrays;
import junit.framework.TestCase;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

public class LIbSecp256k1Test extends TestCase {

  @Test
  public void testOpen() throws IOException {
    PointerByReference ctx = LibSecp256k1.CONTEXT;
    Assert.assertNotNull(ctx);
    final String key = "f31db24bfbd1a2ef19beddca0a0fa37632eded9ac666a05d3bd925f01dde1f62";
    final byte[] privateKey = Hex.decode(key);
    final String messageStr = "f31db24bfbd1a2ef19beddca0a0fa376";
    final byte[] message = Hex.decode(messageStr);

    LibSecp256k1.secp256k1_pubkey pubkey = new LibSecp256k1.secp256k1_pubkey();
    LibSecp256k1.secp256k1_ec_pubkey_create(ctx, pubkey, privateKey);
    LibSecp256k1.secp256k1_ecdsa_recoverable_signature sig = new LibSecp256k1.secp256k1_ecdsa_recoverable_signature();
    LibSecp256k1.secp256k1_ecdsa_sign_recoverable(ctx,sig,message,privateKey,null,null);
    LibSecp256k1.secp256k1_pubkey rePubkey = new LibSecp256k1.secp256k1_pubkey();
    LibSecp256k1.secp256k1_ecdsa_recover(ctx,rePubkey,sig,message);
    Assert.assertTrue(Arrays.equals(pubkey.data,rePubkey.data));
  }
}
