package io.github.redexpress;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.junit.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import static io.github.redexpress.Utils.sha256;

public class CryptographyAlgorithmTest {

	@Test
	public void encode() throws Exception{
		String text = "中文简体";
		String encoded = new Base62x().encodeToBase62xString(text.getBytes(StandardCharsets.UTF_8));
		System.out.println(encoded);
	}

	@Test
	public void ripemd160() throws Exception{
		byte[] in = "Yang".getBytes(StandardCharsets.UTF_8);
		RIPEMD160Digest d = new RIPEMD160Digest();
		d.update(in, 0, in.length);
		byte[] o = new byte[d.getDigestSize()];
		d.doFinal(o, 0);

		System.out.println(Hex.encodeHexString(o));
	}

	@Test
	public void publicKey() {
		String publicKeyX = "41637322786646325214887832269588396900663353932545912953362782457239403430124";
		String publicKeyY = "16388935128781238405526710466724741593761085120864331449066658622400339362166";
		BigInteger x = new BigInteger(publicKeyX);
		BigInteger y = new BigInteger(publicKeyY);
		String comp = "02" + x.toString(16);
		BigInteger value = new BigInteger(comp, 16);
		byte[] hashValue = sha256(value.toByteArray());
		String s = Hex.encodeHexString(hashValue);
		RIPEMD160Digest d = new RIPEMD160Digest();
		d.update(hashValue,0,hashValue.length);
		byte[] hash160ValueWith00Prefix = new byte[d.getDigestSize() + 1];
		d.doFinal(hash160ValueWith00Prefix, 1);
		System.out.println(Hex.encodeHexString(hash160ValueWith00Prefix));
		byte[] doubleHashValue = sha256(sha256(hash160ValueWith00Prefix));
		byte[] finalHashValue = new byte[hash160ValueWith00Prefix.length + 4];
		System.arraycopy(hash160ValueWith00Prefix,0,finalHashValue, 0, hash160ValueWith00Prefix.length);
		System.arraycopy(doubleHashValue,0, finalHashValue, hash160ValueWith00Prefix.length, 4);
		System.out.println(Hex.encodeHexString(finalHashValue));
		String base56Value = Base58.encode(finalHashValue);
		System.out.println("address: " + base56Value);
		System.out.println(s);
		System.out.println(comp);
		System.out.println(x.toString(16) + y.toString(16));
	}

	@Test
	public void testSha256() {
		String s = Hex.encodeHexString(Utils.sha256("ok".getBytes()));
		System.out.println(s);
	}


}
