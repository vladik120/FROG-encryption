package ecdsa;

import java.math.BigInteger;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;

public class ECDSAdata {

	private BigInteger a;
	private BigInteger b;
	private BigInteger n;
	private BigInteger[] G = new BigInteger[2];
	public static final BigInteger[] INFINITY = new BigInteger[2];

	private boolean flag = false;

	public ECDSAdata() {
	}

	public ECDSAdata(int a, int b, int n, BigInteger Gx, BigInteger Gy) {
		
		if (CheckSingularity(BigInteger.valueOf(a), BigInteger.valueOf(b), BigInteger.valueOf(n))) {
			Alert errorAlert = new Alert(AlertType.ERROR);
			errorAlert.setHeaderText("Error!");
			errorAlert.setContentText(" the a and b is not good");
			errorAlert.showAndWait();
			flag = false;
		} else {
			if (!checkOnCurve(BigInteger.valueOf(a), BigInteger.valueOf(b), BigInteger.valueOf(n), Gx, Gy)) {
				Alert errorAlert = new Alert(AlertType.ERROR);
				errorAlert.setHeaderText("Error!");
				errorAlert.setContentText("the point isnt good");
				errorAlert.showAndWait();
				flag = false;
			} else {
				INFINITY[0] = BigInteger.valueOf(-1);
				INFINITY[1] = BigInteger.valueOf(-1);
				this.a = BigInteger.valueOf(a);
				this.b = BigInteger.valueOf(b);
				this.n = BigInteger.valueOf(n);
				G[0] = Gx;
				G[1] = Gy;
				flag = true;
			}

		}

	}

	public BigInteger getB() {
		return b;
	}

	public void setB(BigInteger b) {
		this.b = b;
	}

	public BigInteger getN() {
		return n;
	}

	public void setN(BigInteger n) {
		this.n = n;
	}

	public BigInteger getA() {
		return a;
	}

	public void setA(BigInteger a) {
		this.a = a;
	}

	public BigInteger[] getG() {
		return G;
	}

	public void setG(BigInteger[] g) {
		G = g;
	}

	public boolean isFlag() {
		return flag;
	}

	public void setFlag(boolean flag) {
		this.flag = flag;
	}

	public static boolean checkOnCurve(BigInteger a, BigInteger b, BigInteger n, BigInteger Gx, BigInteger Gy) {
		BigInteger y = Gy.pow(2).mod(n);
		BigInteger x1 = Gx.pow(3);
		BigInteger x2 = Gx.multiply(a).add(b);
		BigInteger x = x1.add(x2);
		return y.equals(x.mod(n)) ? true : false;

	}

	public static boolean CheckSingularity(BigInteger a, BigInteger b, BigInteger n) {
		BigInteger tempBigInteger = a.pow(3).multiply(BigInteger.valueOf(4))
				.add(b.pow(2).multiply(BigInteger.valueOf(27))).mod(n);
		return tempBigInteger.equals(BigInteger.ZERO) ? true : false;
	}

	public static boolean CheckInfinity(BigInteger[] P) {
		return P[0].equals(BigInteger.valueOf(-1)) && P[1].equals(BigInteger.valueOf(-1)) ? true : false;
	}

}
