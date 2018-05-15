namespace AaronLuna.Crypto.SHA3
{
	// Implements a Keccak[c] permutation, which is a Keccak-f[1600] permutation where the rate is determined by the
	// capacity. A Keccak[c] permutation is then a sponge construction with Keccak-p[1600,24] as underlying permutation,
	// pad10*1 as padding rule, and a rate defined by 1600 - c.	
	public class Keccak : KeccakFunction
	{
		public Keccak(int capacity)
		    : base(SpongeSize.W64, 1600 - capacity) { }

	    public static Keccak Keccak224()
	    {
			return new Keccak(448);
		}

		public static Keccak Keccak256()
		{
			return new Keccak(512);
		}

		public static Keccak Keccak384()
		{
			return new Keccak(768);
		}

		public static Keccak Keccak512()
		{
			return new Keccak(1024);
		}
	}
}
