package app;

import java.math.BigInteger;

public class Message {
	private byte[] EncryptedKey;
	private byte[] EncText;
	private BigInteger[] Sign;

	public Message() {

	}

	public Message(byte[] encryptedKey, byte[] encText) {
		super();
		EncryptedKey = encryptedKey;
		EncText = encText;
	}

	public byte[] getEncryptedKey() {
		return EncryptedKey;
	}

	public void setEncryptedKey(byte[] encryptedKey) {
		EncryptedKey = encryptedKey;
	}

	public byte[] getEncText() {
		return EncText;
	}

	public void setEncText(byte[] encText) {
		EncText = encText;
	}

	public BigInteger[] getSign() {
		return Sign;
	}

	public void setSign(BigInteger[] sign) {
		Sign = sign;
	}
}
