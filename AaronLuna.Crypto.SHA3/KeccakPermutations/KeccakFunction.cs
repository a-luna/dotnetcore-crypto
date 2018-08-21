namespace AaronLuna.Crypto.SHA3
{
    // Implements a Keccak-f[b] permutation, which is a Keccak-p[b,nr] permutation
    // specialized to the case where nr = 12 + 2 * L
	public class KeccakFunction : KeccakPermutation
	{
		protected KeccakFunction(SpongeSize size, int rate)
			: base(size, rate, 12 + (size.L << 1)) { }

		public static KeccakFunction F25(int rate)
		{
			return new KeccakFunction(SpongeSize.W01, rate);
		}

		public static KeccakFunction F50(int rate)
		{
			return new KeccakFunction(SpongeSize.W02, rate);
		}

		public static KeccakFunction F100(int rate)
		{
			return new KeccakFunction(SpongeSize.W04, rate);
		}

		public static KeccakFunction F200(int rate)
		{
			return new KeccakFunction(SpongeSize.W08, rate);
		}

		public static KeccakFunction F400(int rate)
		{
			return new KeccakFunction(SpongeSize.W16, rate);
		}

		public static KeccakFunction F800(int rate)
		{
			return new KeccakFunction(SpongeSize.W32, rate);
		}

		public static KeccakFunction F1600(int rate)
		{
			return new KeccakFunction(SpongeSize.W64, rate);
		}
	}
}
