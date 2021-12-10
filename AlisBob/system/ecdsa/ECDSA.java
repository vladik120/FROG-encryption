package ecdsa;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;

public class ECDSA {

	public static BigInteger[] createSignature(byte[] msg, ECDSAdata curve, BigInteger privatekey) {
		BigInteger[] sign = new BigInteger[2];
		int nLength = 0;
		byte[] z;

		byte[] e = null;
		BigInteger[] XYtempBigInteger = new BigInteger[2];

		BigInteger kBigInteger;
		BigInteger zBigInteger;
		BigInteger rBigInteger;
		BigInteger sBigInteger;
		Random rand = new Random();
		int k;
		;
		// set n length in byte
		nLength = curve.getN().bitLength();
		z = new byte[nLength];
		// hash the message
		try {
			e = Hash(msg);
		} catch (NoSuchAlgorithmException error) {
			error.printStackTrace();
			Alert errorAlert = new Alert(AlertType.ERROR);
			errorAlert.setHeaderText("Error!");
			errorAlert.setContentText("cant hash the Message");
			errorAlert.showAndWait();
			return sign;
		}
		// make Z
		for (int i = 0; i < nLength; i++) {
			z[i] = e[i];
		}

		zBigInteger = new BigInteger(z);
		// for K

		do {

			do {
				k = rand.nextInt(curve.getN().intValue() - 1);
				if (k < 2)
					k = 2;
				kBigInteger = BigInteger.valueOf(k).mod(curve.getN());
				XYtempBigInteger = MultiPoint(curve.getN(), curve.getG(), kBigInteger, curve.getA());
				rBigInteger = XYtempBigInteger[0].mod(curve.getN());
			} while (rBigInteger.equals(BigInteger.ZERO) || ECDSAdata.CheckInfinity(XYtempBigInteger));

			// k^-1
			kBigInteger = kBigInteger.modInverse(curve.getN());
			sBigInteger = kBigInteger.multiply(zBigInteger.add(rBigInteger.multiply(privatekey)));
			sBigInteger = sBigInteger.mod(curve.getN());
		} while (sBigInteger.equals(BigInteger.ZERO));

		sign[0] = rBigInteger;
		sign[1] = sBigInteger;
		return sign;
	}

	public static boolean checkSignature(BigInteger[] sign, ECDSAdata curve, BigInteger[] publicPoint, byte[] msg) {

		BigInteger[] temp = new BigInteger[2];
		BigInteger[] U = new BigInteger[2];
		BigInteger[] result = new BigInteger[2];
		BigInteger wBigInteger;
		byte[] e = null;
		byte[] z;
		int nLength = 0;
		BigInteger zBigInteger;
		BigInteger sBigInteger = sign[1];
		BigInteger rBigInteger = sign[0];
		BigInteger[] temp1BigInteger;
		BigInteger[] temp2BigInteger;
		// set n length in byte
		nLength = curve.getN().bitLength();
		z = new byte[nLength];
		// check if equals O
		if (checkIfO(publicPoint)) {
			return false;
		}
		// on the curve
		if (!ECDSAdata.checkOnCurve(curve.getA(), curve.getB(), curve.getN(), publicPoint[0], publicPoint[1])) {
			return false;
		}
		// check if n*(curve public key) equals 0
		temp = MultiPoint(curve.getN(), publicPoint, curve.getN(), curve.getA());
		if (!ECDSAdata.CheckInfinity(temp)) {
			return false;
		}

		// check if sign is between 1 and n-1
		if (!checkIfInRange(sign, curve.getN())) {
			System.out.println("[checkSignature] int the checkIfInRange ");
			System.out.println("[checkSignature] the sign is " + Arrays.toString(sign));
			System.out.println("[checkSignature] the publicPoint is " + Arrays.toString(publicPoint));
			System.out.println("[checkSignature] the n is " + curve.getN());
			return false;
		}
		// hash function
		try {
			e = Hash(msg);
		} catch (NoSuchAlgorithmException error) {
			error.printStackTrace();
			Alert errorAlert = new Alert(AlertType.ERROR);
			errorAlert.setHeaderText("Error!");
			errorAlert.setContentText("cant hash the Message");
			errorAlert.showAndWait();
			return false;
		}
		// get the Z
		for (int i = 0; i < nLength; i++) {
			z[i] = e[i];
		}
		zBigInteger = new BigInteger(z);
		// get the W
		wBigInteger = sBigInteger.modInverse(curve.getN());
		// get U1 and U2
		U[0] = zBigInteger.multiply(wBigInteger).mod(curve.getN());
		U[1] = rBigInteger.multiply(wBigInteger).mod(curve.getN());
		// get X,Y
		temp1BigInteger = MultiPoint(curve.getN(), curve.getG(), U[0], curve.getA());
		temp2BigInteger = MultiPoint(curve.getN(), publicPoint, U[1], curve.getA());
		result = AddPoint(temp1BigInteger, temp2BigInteger, curve.getN(), curve.getA());
		// check is X,Y is O
		if (checkIfO(result)) {
			return false;
		}
		// Check if the sign is valid
		if (rBigInteger.equals(result[0].mod(curve.getN())))
			return true;
		return false;

	}

	public static BigInteger[] MultiPoint(BigInteger n, BigInteger[] P, BigInteger mult, BigInteger a) {
		BigInteger[] resultPoint = new BigInteger[2];
		int multint = mult.intValue();
		resultPoint = P;
		for (int i = 0; i < multint - 1; i++)
			resultPoint = AddPoint(resultPoint, P, n, a);

		return resultPoint;
	}

	public static BigInteger[] AddSamePoint(BigInteger n, BigInteger[] P, BigInteger a) {
		BigInteger[] resultPoint = new BigInteger[2];
		BigInteger m;
		BigInteger temp1BigInteger;
		BigInteger temp2BigInteger;

		temp1BigInteger = P[0].pow(2).multiply(BigInteger.valueOf(3)).add(a);
		temp2BigInteger = P[1].multiply(BigInteger.valueOf(2));

		temp2BigInteger = temp2BigInteger.modInverse(n);

		m = temp1BigInteger.multiply(temp2BigInteger).mod(n);

		temp1BigInteger = m.pow(2).subtract(P[0].multiply(BigInteger.valueOf(2)));
		resultPoint[0] = temp1BigInteger.mod(n);

		temp1BigInteger = m.multiply(P[0].subtract(resultPoint[0])).subtract(P[1]);
		resultPoint[1] = temp1BigInteger.mod(n);

		return resultPoint;
	}

	public static BigInteger[] AddDifPoint(BigInteger n, BigInteger[] P1, BigInteger[] P2) {
		BigInteger[] resultPoint = new BigInteger[2];
		BigInteger m;
		BigInteger temp1BigInteger;
		BigInteger temp2BigInteger;

		temp1BigInteger = P2[1].subtract(P1[1]);
		temp2BigInteger = P2[0].subtract(P1[0]);

		temp2BigInteger = temp2BigInteger.modInverse(n);

		m = temp1BigInteger.multiply(temp2BigInteger).mod(n);

		temp1BigInteger = m.pow(2).subtract(P1[0]).subtract(P2[0]);
		resultPoint[0] = temp1BigInteger.mod(n);

		temp1BigInteger = m.multiply(P1[0].subtract(resultPoint[0])).subtract(P1[1]);
		resultPoint[1] = temp1BigInteger.mod(n);

		return resultPoint;
	}

	public static BigInteger[] AddPoint(BigInteger[] P1, BigInteger[] P2, BigInteger n, BigInteger a) {

		if (ECDSAdata.CheckInfinity(P1))
			return P2;
		if (ECDSAdata.CheckInfinity(P2))
			return P1;

		if (P1[0].equals(P2[0]) && P1[1].equals(P2[1].multiply(BigInteger.valueOf(-1)).mod(n)))
			return ECDSAdata.INFINITY;

		if (PointEqual(P1, P2))
			return AddSamePoint(n, P1, a);

		return AddDifPoint(n, P1, P2);
	}

	public static boolean PointEqual(BigInteger[] P1, BigInteger[] P2) {
		if (P1[0].equals(P2[0]))
			if (P1[1].equals(P2[1]))
				return true;
		return false;
	}

	public static boolean checkIfInRange(BigInteger[] P, BigInteger n) {
		if (P[0].compareTo(n) >= 0)
			return false;
		if (P[0].compareTo(BigInteger.ZERO) == -1)
			return false;
		if (P[1].compareTo(n) >= 0)
			return false;
		if (P[0].compareTo(BigInteger.ZERO) == -1)
			return false;
		return true;
	}

	public static boolean checkIfO(BigInteger[] P) {
		if (P[0].equals(BigInteger.valueOf(-1)))
			return true;
		return false;
	}

	public static byte[] Hash(byte[] Msg) throws NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		byte[] hash = digest.digest(Msg);
		return hash;
	}

	public static void main(String[] args) {
		ECDSAdata curve = new ECDSAdata(-2, 15, 23, BigInteger.valueOf(4), BigInteger.valueOf(5));
		// curve = new ECDSAdata();
		byte[] text = new byte[256];
		int count = 0;
		int k;
		BigInteger[] sign;
		BigInteger privatekey ;
		BigInteger[] publicPoint;
		Random rand = new Random();
		
		for (int i = 0; i < 256; i++)
			text[i] = (byte) i;

		for (int i = 0; i < 10000; i++) {
			k = rand.nextInt(curve.getN().intValue() - 1);
			if (k < 2)
				k = 2;
			privatekey = BigInteger.valueOf(k).mod(curve.getN());
			
			publicPoint = MultiPoint(curve.getN(), curve.getG(), privatekey, curve.getA());
			sign = createSignature(text, curve, privatekey);
			if (checkSignature(sign, curve, publicPoint, text))
				count++;
			else
				System.out.println("");
		}
		System.out.println("from 10000 tests the secsses was " + count);

	}
}
