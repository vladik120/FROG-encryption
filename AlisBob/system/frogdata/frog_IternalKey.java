package frogdata;

public class frog_IternalKey {
	public int xorBu[];
	public int SubstPermu[];
	public int BombPermu[];

	public frog_IternalKey() {
		xorBu = new int[frog_Properties.BLOCK_SIZE];
		SubstPermu = new int[256];
		BombPermu = new int[frog_Properties.BLOCK_SIZE];
	}

	public static int size() {
		return frog_Properties.BLOCK_SIZE * 2 + 256;
	}

	public void setValue(int index, int value) {
		if (value < 0)
			value = 256 + value;
		if (index < frog_Properties.BLOCK_SIZE)
			xorBu[index] = value;
		else if (index < frog_Properties.BLOCK_SIZE + 256)
			SubstPermu[index - frog_Properties.BLOCK_SIZE] = value;
		else
			BombPermu[index - frog_Properties.BLOCK_SIZE - 256] = value;
	}

	public int getValue(int index) {
		if (index < frog_Properties.BLOCK_SIZE)
			return xorBu[index];
		else if (index < frog_Properties.BLOCK_SIZE + 256)
			return SubstPermu[index - frog_Properties.BLOCK_SIZE];
		else
			return BombPermu[index - frog_Properties.BLOCK_SIZE - 256];
	}

	public void CopyFrom(frog_IternalKey ori) {
		int i;
		for (i = 0; i < ori.xorBu.length; i++)
			xorBu[i] = ori.xorBu[i];
		for (i = 0; i < ori.SubstPermu.length; i++)
			SubstPermu[i] = ori.SubstPermu[i];
		for (i = 0; i < ori.BombPermu.length; i++)
			BombPermu[i] = ori.BombPermu[i];
	}

	public static boolean checkqual(frog_IternalKey[] first, frog_IternalKey[] second) {
		for (int j = 0; j < frog_Properties.numIter; j++) {
			for (int i = 0; i < second[j].xorBu.length; i++)
				if(first[j].xorBu[i] != second[j].xorBu[i])
					return false;
			for (int i = 0; i < second[j].SubstPermu.length; i++)
				if(first[j].SubstPermu[i] != second[j].SubstPermu[i])
					return false;
			for (int i = 0; i < second[j].BombPermu.length; i++)
				if(first[j].BombPermu[i] != second[j].BombPermu[i])
					return false;
		}
		return true;
	}

}
