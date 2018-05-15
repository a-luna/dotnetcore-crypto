namespace AaronLuna.Crypto.SHA3
{
	public sealed class Sha3Permutation : Keccak
	{
		public int Width => Capacity >> 1;

	    Sha3Permutation(int capacity)
			: base(capacity) { }

		public static Sha3Permutation Sha3_224()
		{
			return new Sha3Permutation(448);
		}

		public static Sha3Permutation Sha3_256()
		{
			return new Sha3Permutation(512);
		}

		public static Sha3Permutation Sha3_384()
		{
			return new Sha3Permutation(768);
		}

		public static Sha3Permutation Sha3_512()
		{
			return new Sha3Permutation(1024);
		}

		protected override BitString Suffix()
		{
			return new BitString("01");
		}
	}
}
