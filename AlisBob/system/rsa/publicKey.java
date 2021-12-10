package rsa;

public class publicKey {
	private int n;
	private int publicKey;

	public publicKey(int prime1, int prime2, int publickey) {
		this.publicKey = publickey;
		this.n = prime1 * prime2;
	}

	public int getPublicKey() {
		return publicKey;
	}

	public int getN() {
		return n;
	}
}
