package rsa;

@SuppressWarnings("unused")
public class secretKey {
	private int p1;
	private int p2;
	private int phi;
	private int n;
	private int privateKey;
	private int publicKey;

	public secretKey(int p1, int p2, int publicKey) {
		this.p1 = p1;
		this.p2 = p2;
		this.publicKey = publicKey;
		phi = (p1 - 1) * (p2 - 1);
		n = p1 * p2;
		privateKey = calcPrivateKey(publicKey);
	}

	private int calcPrivateKey(int e) {
		int result;
		int k = 0;
		while (true) {
			result = (k * phi + 1) / publicKey;
			if ((result * publicKey) % phi == 1) {
				return result;
			} else
				k++;
		}
	}

	public int getPhi() {
		return phi;
	}

	public int getPrivateKey() {
		return privateKey;
	}

	public int getN() {
		return n;
	}

}
