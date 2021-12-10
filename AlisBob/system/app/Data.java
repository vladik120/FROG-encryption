package app;

import java.math.BigInteger;

import rsa.publicKey;
import rsa.secretKey;

public class Data {
	private publicKey MyPublicKey;
	private secretKey MySecretKey;
	private publicKey PublicFrom;
	private BigInteger[] A;
	private BigInteger privateSignKey;
	

	

	private byte[] MyKey;

	
	public Data(publicKey myPublicKey, secretKey mySecretKey, publicKey publicFrom, byte[] myKey) {
		super();
		MyPublicKey = myPublicKey;
		MySecretKey = mySecretKey;
		PublicFrom = publicFrom;
		MyKey = myKey;
	}


	public Data() {
		MyPublicKey = null;
		MySecretKey = null;
		PublicFrom = null;
		MyKey = null;
	}


	public publicKey getMyPublicKey() {
		return MyPublicKey;
	}

	public void setMyPublicKey(publicKey myPublicKey) {
		MyPublicKey = myPublicKey;
	}

	public secretKey getMySecretKey() {
		return MySecretKey;
	}

	public void setMySecretKey(secretKey mySecretKey) {
		MySecretKey = mySecretKey;
	}

	public publicKey getPublicFrom() {
		return PublicFrom;
	}

	public void setPublicFrom(publicKey publicFrom) {
		PublicFrom = publicFrom;
	}

	public byte[] getMyKey() {
		return MyKey;
	}

	public void setMyKey(byte[] myKey) {
		MyKey = myKey;
	}


	public BigInteger[] getA() {
		return A;
	}


	public void setA(BigInteger[] a) {
		A = a;
	}
	
	public BigInteger getPrivateSignKey() {
		return privateSignKey;
	}


	public void setPrivateSignKey(BigInteger privateSignKey) {
		this.privateSignKey = privateSignKey;
	}



}
