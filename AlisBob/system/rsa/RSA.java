package rsa;

import java.math.BigInteger;
import java.util.Random;

public class RSA {

	public static byte[] startRSAEncryption(publicKey PK, byte[] Msg) {
		byte[] ciphertext;
		BigInteger MsgInteger = new BigInteger(Msg);
		BigInteger privateInteger = BigInteger.valueOf(PK.getN());
		MsgInteger.pow(PK.getPublicKey());
		MsgInteger.mod(privateInteger);
		ciphertext = MsgInteger.toByteArray();
		return ciphertext;
	}

	public static byte[] startRSADecryption(secretKey SK, byte[] Msg) {
		byte[] plaintext;
		BigInteger MsgInteger = new BigInteger(Msg);
		BigInteger privateInteger = BigInteger.valueOf(SK.getN());
		MsgInteger.pow(SK.getPrivateKey());
		MsgInteger.mod(privateInteger);
		plaintext = MsgInteger.toByteArray();
		return plaintext;
	}

	public static void main(String[] args) {
		String plainString = new String("this is the plain text");
		byte[] plainByte = plainString.getBytes();
		byte[] cipherByte;
		publicKey pKey = new publicKey(7, 17, 13);
		secretKey sKey = new secretKey(7, 17, 13);
		int count = 0;
		int test = 100;

		for (int i = 1; i <= test; i++) {
			plainByte = makeText(i);
			cipherByte = RSA.startRSAEncryption(pKey, plainByte);
			if(checkEqual(plainByte,RSA.startRSADecryption(sKey, cipherByte)))
				count++;
		}

		System.out.println("[test RSA] for testing "+test+" the RSA work "+count);

	}

	public static byte[] makeText(int size) {
		byte[] key = new byte[size];
		Random rand = new Random();
		for (int i = 0; i < size; i++)
			key[i] = (byte) rand.nextInt(128);
		return key;

	}

	public static boolean checkEqual(byte[] a, byte[] b) {
		for (int i = 0; i < a.length; i++) 
			if(a[i] != b[i])
				return false;
		return true;
	}

}
