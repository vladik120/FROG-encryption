package frog;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;

import frogdata.frog_IternalKey;
import frogdata.frog_Properties;
public class FROG {

	private static int[] randomSeed = { 113, 21, 232, 18, 113, 92, 63, 157, 124, 193, 166, 197, 126, 56, 229, 229, 156,
			162, 54, 17, 230, 89, 189, 87, 169, 0, 81, 204, 8, 70, 203, 225, 160, 59, 167, 189, 100, 157, 84, 11, 7,
			130, 29, 51, 32, 45, 135, 237, 139, 33, 17, 221, 24, 50, 89, 74, 21, 205, 191, 242, 84, 53, 3, 230, 231,
			118, 15, 15, 107, 4, 21, 34, 3, 156, 57, 66, 93, 255, 191, 3, 85, 135, 205, 200, 185, 204, 52, 37, 35, 24,
			68, 185, 201, 10, 224, 234, 7, 120, 201, 115, 216, 103, 57, 255, 93, 110, 42, 249, 68, 14, 29, 55, 128, 84,
			37, 152, 221, 137, 39, 11, 252, 50, 144, 35, 178, 190, 43, 162, 103, 249, 109, 8, 235, 33, 158, 111, 252,
			205, 169, 54, 10, 20, 221, 201, 178, 224, 89, 184, 182, 65, 201, 10, 60, 6, 191, 174, 79, 98, 26, 160, 252,
			51, 63, 79, 6, 102, 123, 173, 49, 3, 110, 233, 90, 158, 228, 210, 209, 237, 30, 95, 28, 179, 204, 220, 72,
			163, 77, 166, 192, 98, 165, 25, 145, 162, 91, 212, 41, 230, 110, 6, 107, 187, 127, 38, 82, 98, 30, 67, 225,
			80, 208, 134, 60, 250, 153, 87, 148, 60, 66, 165, 72, 29, 165, 82, 211, 207, 0, 177, 206, 13, 6, 14, 92,
			248, 60, 201, 132, 95, 35, 215, 118, 177, 121, 180, 27, 83, 131, 26, 39, 46, 12 };

	public FROG(String key) {

	}

	public static byte[] StartEncryption(byte[] plaintext, byte[] key) {
		byte[][] plaintextdiv;
		byte[] ciphertext = null;
		int j;
		int plaintextlength = plaintext.length;
		ByteBuffer buff = ByteBuffer.wrap(SetBuffArray(plaintext));

		if (plaintextlength > frog_Properties.BLOCK_SIZE) {
			plaintextdiv = divToBlock(plaintext);

			for (j = 0; j < plaintextlength / frog_Properties.BLOCK_SIZE; j++) {
				buff.put(FROGEncryption(plaintextdiv[j], KetSetup(frog_Properties.Encription, key)));
			}
			if (plaintextlength % frog_Properties.BLOCK_SIZE != 0)
				buff.put(FROGEncryption(plaintextdiv[j], KetSetup(frog_Properties.Encription, key)));

			ciphertext = buff.array();
		} else
			ciphertext = FROGEncryption(plaintext, KetSetup(frog_Properties.Encription, key));

		return ciphertext;
	}

	public static byte[] StartDecryption(byte[] ciphertext, byte[] key) {
		byte[][] ciphertextdiv;
		byte[] plaintext = null;
		int j;
		int ciphertextlength = ciphertext.length;
		ByteBuffer buff;

		if (ciphertextlength > frog_Properties.BLOCK_SIZE) {
			ciphertextdiv = divToBlock(ciphertext);
			buff = ByteBuffer.wrap(SetBuffArray(ciphertext));

			for (j = 0; j < ciphertextlength / frog_Properties.BLOCK_SIZE; j++) {
				buff.put(FROGDecryption(ciphertextdiv[j], KetSetup(frog_Properties.Decription, key)));
			}
			if (ciphertextlength % frog_Properties.BLOCK_SIZE != 0)
				buff.put(FROGDecryption(ciphertextdiv[j], KetSetup(frog_Properties.Decription, key)));

			plaintext = buff.array();
		} else
			plaintext = FROGDecryption(ciphertext, KetSetup(frog_Properties.Decription, key));

		return plaintext;
	}

	private static byte[] FROGEncryption(byte[] plainText, frog_IternalKey[] internKey) {
		int k;
		if (plainText.length < frog_Properties.BLOCK_SIZE)
			plainText = Fill(plainText);

		for (int InterNum = 0; InterNum < frog_Properties.numIter; InterNum++) {
			for (int byteNum = 0; byteNum < frog_Properties.BLOCK_SIZE; byteNum++) {
				plainText[byteNum] ^= internKey[InterNum].xorBu[byteNum];
				if (plainText[byteNum] < 0)
					plainText[byteNum] = (byte) internKey[InterNum].SubstPermu[plainText[byteNum] + 256];
				else
					plainText[byteNum] = (byte) internKey[InterNum].SubstPermu[plainText[byteNum]];

				if (byteNum < frog_Properties.BLOCK_SIZE - 1)
					plainText[byteNum + 1] ^= plainText[byteNum];
				else
					plainText[0] ^= plainText[frog_Properties.BLOCK_SIZE - 1];

				k = internKey[InterNum].BombPermu[byteNum];
				plainText[k] ^= plainText[byteNum];
			}
		}
		return plainText;
	}

	private static byte[] FROGDecryption(byte[] ciphertext, frog_IternalKey[] internKey) {

		int k;
		if (ciphertext.length < frog_Properties.BLOCK_SIZE)
			ciphertext = Fill(ciphertext);

		for (int InterNum = frog_Properties.numIter - 1; InterNum >= 0; InterNum--) {
			for (int byteNum = frog_Properties.BLOCK_SIZE - 1; byteNum >= 0; byteNum--) {
				k = internKey[InterNum].BombPermu[byteNum];
				ciphertext[k] ^= ciphertext[byteNum];
				if (byteNum < frog_Properties.BLOCK_SIZE - 1)
					ciphertext[byteNum + 1] ^= ciphertext[byteNum];
				else
					ciphertext[0] ^= ciphertext[frog_Properties.BLOCK_SIZE - 1];

				if (ciphertext[byteNum] < 0)
					ciphertext[byteNum] = (byte) internKey[InterNum].SubstPermu[ciphertext[byteNum] + 256];
				else
					ciphertext[byteNum] = (byte) internKey[InterNum].SubstPermu[ciphertext[byteNum]];

				ciphertext[byteNum] ^= internKey[InterNum].xorBu[byteNum];
			}

		}
		return ciphertext;

	}

	// step 1 - make simple key
	private static frog_IternalKey[] MakeSimpleKey(byte[] UserKey, int keyLenght) {

		int S = 0, K = 0;
		frog_IternalKey simplekey[] = new frog_IternalKey[frog_Properties.numIter];
		int simplykeyBytes = frog_Properties.numIter * frog_IternalKey.size();

		for (int i = 0; i < frog_Properties.numIter; i++)
			simplekey[i] = new frog_IternalKey();

		for (int i = 0; i < simplykeyBytes; i++) {
			simplekey[i / frog_IternalKey.size()].setValue(i % frog_IternalKey.size(), randomSeed[S] ^ UserKey[K]);
			if (S < 250)
				S++;
			else
				S = 0;
			if (K < keyLenght - 1)
				K++;
			else
				K = 0;

		}
		return simplekey;
	}

	// step 2 -
	private static byte[] MakeInitializationVector(byte[] UserKey, int keylenght) {

		byte IV[] = new byte[frog_Properties.BLOCK_SIZE];
		int last = keylenght - 1;

		for (int i = 0; i < frog_Properties.BLOCK_SIZE; i++)
			IV[i] = 0;

		if (last > frog_Properties.BLOCK_SIZE)
			last = frog_Properties.BLOCK_SIZE - 1;
		for (int i = 0; i < last; i++)
			IV[i] = (byte) (IV[i] ^ UserKey[i]);
		IV[0] = (byte) (IV[0] ^ keylenght);
		return IV;
	}

	private static frog_IternalKey[] FrogModeOFB(byte[] IV, frog_IternalKey[] internKey) {

		byte[] IVnew = IV;
		int IVcount = 0;
		frog_IternalKey[] randomkey = new frog_IternalKey[frog_Properties.numIter];

		for (int i = 0; i < frog_Properties.numIter; i++)
			randomkey[i] = new frog_IternalKey();

		for (int i = 0; i < frog_Properties.numIter; i++) {
			for (int j = 0; j < frog_IternalKey.size(); j++, IVcount++) {
				if (IVcount == frog_Properties.BLOCK_SIZE) {
					IVnew = FROGEncryption(IVnew, internKey);
					IVcount = 0;
				}
				randomkey[i].setValue(j, IVnew[IVcount] ^ 0);

				if (IVnew[IVcount] < 0)
					randomkey[i].setValue(j, (IVnew[IVcount] + 256) ^ 0);
				else
					randomkey[i].setValue(j, IVnew[IVcount] ^ 0);

			}
		}

		return randomkey;
	}

	private static frog_IternalKey[] MakeInternalKey(int state, frog_IternalKey[] simpleKey) {

		frog_IternalKey[] internalKey = new frog_IternalKey[frog_Properties.numIter];

		for (int i = 0; i < frog_Properties.numIter; i++) {
			internalKey[i] = new frog_IternalKey();

			internalKey[i].SubstPermu = MakePermutation(simpleKey[i].SubstPermu);

			if (state == frog_Properties.Decription)
				internalKey[i].SubstPermu = invertPermutation(internalKey[i].SubstPermu);

			internalKey[i].BombPermu = MakePermutation(simpleKey[i].BombPermu);

			internalKey[i].BombPermu = Validate(internalKey[i].BombPermu);

		}
		return internalKey;
	}

	private static int[] Validate(int[] Permu) {
		int bombPermu[] = Permu;
		int used[] = new int[frog_Properties.BLOCK_SIZE];
		int index = 0;
		int K = 0;
		int L;
		for (int i = 0; i < used.length; i++)
			used[i] = 0;

		for (int i = 0; i < frog_Properties.BLOCK_SIZE - 1; i++) {
			if (bombPermu[index] == 0) {
				K = index;
				do {
					K = (K + 1) % frog_Properties.BLOCK_SIZE;
				} while (used[K] != 0);
				bombPermu[index] = K;
				L = K;
				while (bombPermu[L] != K)
					L = bombPermu[L];

				bombPermu[L] = 0;

			}
			used[index] = 1;
			index = bombPermu[index];
		}
		// --------------?????????????--------------------
		for (int i = 0; i < frog_Properties.BLOCK_SIZE; i++) {
			if (bombPermu[i] == (i + 1) % frog_Properties.BLOCK_SIZE)
				bombPermu[i] = (i + 2) % frog_Properties.BLOCK_SIZE;
		}

		return bombPermu;
	}

	private static int[] MakePermutation(int[] Perm) {
		int substPermu[] = new int[Perm.length];
		int use[] = new int[256];
		int lastElement = Perm.length - 1;
		int last = lastElement;
		int index = 0;

		for (int i = 0; i < Perm.length; i++)
			substPermu[i] = Perm[i];

		for (int i = 0; i <= lastElement; i++)
			use[i] = i;

		for (int i = 0; i < lastElement; i++) {
			index = (index + substPermu[i]) % (last + 1);
			substPermu[i] = use[index];
			if (index < last)
				for (int k = index; k <= last - 1; k++)
					use[k] = use[k + 1];
			last--;
			if (index > last)
				index = 0;

		}
		substPermu[lastElement] = use[0];

		return substPermu;
	}

	private static frog_IternalKey[] HashKey(byte[] userKey) {
		// Step 1 - make simple key
		frog_IternalKey[] simplekey = MakeSimpleKey(userKey, userKey.length);
		// make internal key
		frog_IternalKey[] internalKey = MakeInternalKey(frog_Properties.Encription, simplekey);
		// step 2 -
		byte[] IV = MakeInitializationVector(userKey, userKey.length);
		// step 3 - random key
		frog_IternalKey[] randomKey = FrogModeOFB(IV, internalKey);
		return randomKey;
	}

	private static frog_IternalKey[] KetSetup(int state, byte[] userKey) {
		return MakeInternalKey(state, HashKey(userKey));
	}

	private static byte[] Fill(byte[] array) {
		int count = 0;
		byte zero[] = new byte[frog_Properties.BLOCK_SIZE];
		for (int i = 0; i < frog_Properties.BLOCK_SIZE; i++, count++) {
			if (count >= array.length)
				zero[i] = 32;
			else
				zero[i] = array[count];
		}
		return zero;
	}

	private static int[] invertPermutation(int[] orig) {

		int invert[] = new int[256];
		int i, lastElem = orig.length - 1;
		for (i = 0; i <= lastElem; i++)
			invert[orig[i]] = i;
		return invert;
	}

	private static byte[][] divToBlock(byte[] text) {
		int textlength = text.length;
		int lower = 0, upper = frog_Properties.BLOCK_SIZE;
		byte[][] textdiv;
		int i;

		if (textlength % frog_Properties.BLOCK_SIZE == 0)
			textdiv = new byte[(textlength / frog_Properties.BLOCK_SIZE)][16];
		else
			textdiv = new byte[(textlength / frog_Properties.BLOCK_SIZE) + 1][16];

		for (i = 0; i < textlength / frog_Properties.BLOCK_SIZE; i++) {
			textdiv[i] = Arrays.copyOfRange(text, lower, upper);
			lower += frog_Properties.BLOCK_SIZE;
			upper += frog_Properties.BLOCK_SIZE;
		}
		if (textlength % frog_Properties.BLOCK_SIZE != 0)
			textdiv[i] = Arrays.copyOfRange(text, lower, (textlength % frog_Properties.BLOCK_SIZE) + lower);
		return textdiv;
	}

	private static byte[] SetBuffArray(byte[] text) {
		byte[] buff;
		if (text.length % frog_Properties.BLOCK_SIZE != 0)
			buff = new byte[((text.length / frog_Properties.BLOCK_SIZE) + 1) * frog_Properties.BLOCK_SIZE];
		else
			buff = new byte[text.length];
		return buff;
	}

	public static byte[] makeKey(int size) {
		byte[] key = new byte[size];
		Random rand = new Random();
		for (int i = 0; i < size; i++)
			key[i] = (byte) rand.nextInt(128);
		return key;

	}

	public static void main(String args[]) throws Exception {
		String textString = new String("a a a a a a a a a a a a a a a a a a a a a a a");
		String keyString = new String("1111111111");
		if (textString.length() < frog_Properties.BLOCK_SIZE)
			System.out.println("the new plain text is : '" + Arrays.toString(Fill(textString.getBytes())) + "'");
		System.out.println("the plaintext was : " + textString);
		System.out.println("the plaintext was in byte : " + Arrays.toString(textString.getBytes()));
		System.out.println("the lenght of plaintext is : " + textString.getBytes().length);
		System.out.println("the key is " + keyString);
		System.out.println("the key in byte is " + Arrays.toString(keyString.getBytes()));

		byte[] cipherByte = FROG.StartEncryption(textString.getBytes(), keyString.getBytes());
		String cipherString = new String(cipherByte);
		System.out.println("the ciphertext in byte is : " + Arrays.toString(cipherByte));
		System.out.println("the ciphertext length : " + cipherByte.length);
		System.out.println("the ciphertext is : '" + cipherString + "'");
		System.out.println("the key in byte is " + Arrays.toString(keyString.getBytes()));

		byte[] plainByte = FROG.StartDecryption(cipherByte, keyString.getBytes());
		String plainString = new String(plainByte);
		System.out.println("the plaintext in byte is : " + Arrays.toString(plainByte));
		System.out.println("the plaintext length : " + plainByte.length);
		System.out.println("the plaintext is  : '" + plainString + "'");
		System.out.println("the key in byte is " + Arrays.toString(keyString.getBytes()));
	}
}
