package io.github.redexpress;

import com.chrylis.codec.base58.Base58Codec;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.junit.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import static io.github.redexpress.Utils.*;

public class CryptographyAlgorithmTest {

	@Test
	public void encode() throws Exception{
		String text = "中文简体";
		String encoded = encodeToBase62xString(text.getBytes(StandardCharsets.UTF_8));
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

	public String address(byte[] bytes){
		boolean comp = (bytes[0] != 4);
		byte[] hashValue = sha256(bytes);
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
		String base56Value = base58encode(finalHashValue);
		byte[] decode = Utils.base58decode(base56Value);
		System.out.println("de " + Hex.encodeHexString(decode));
		System.out.println("address " + (comp ? " comp: " : "nocomp: ") + base56Value);
		System.out.println(s);
		return base56Value;
	}

	@Test
	public void publicKey() {
		String publicKeyX = "41637322786646325214887832269588396900663353932545912953362782457239403430124";
		String publicKeyY = "16388935128781238405526710466724741593761085120864331449066658622400339362166";
		BigInteger x = new BigInteger(publicKeyX);
		BigInteger y = new BigInteger(publicKeyY);
		byte[] comp = merge((byte)2, x.toByteArray());
		System.out.println(address(comp));

		byte[] nocomp = merge(merge((byte)4, x.toByteArray()), y.toByteArray());
		System.out.println(address(nocomp));


		byte[] publicKey = new BigInteger("044dd258cc3e050b570299ef45de5d96e524051096a2a9ae52d22ba8927b167fcef297f35a0de8b7c5789264d2de858dc8582c39368c399fd91dc5a92c33d85aa1", 16).toByteArray();
		System.out.println(address(publicKey));

	}


	@Test
	public void testECC() throws Exception
	{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
		keyPairGenerator.initialize(256, new SecureRandom());
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		String s = keyPair.getPublic().toString();
		System.out.println(s);
	}

	@Test
	public void testSha256() {
		String s = Hex.encodeHexString(Utils.sha256("ok".getBytes()));
		System.out.println(s);
	}


}
