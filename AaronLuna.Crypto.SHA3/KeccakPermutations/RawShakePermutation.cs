namespace AaronLuna.Crypto.SHA3
{
	public sealed class RawShakePermutation : Keccak
	{
		RawShakePermutation(int capacity)
			: base(capacity) { }

		public static RawShakePermutation RawShake128()
		{
			return new RawShakePermutation(256);
		}

		public static RawShakePermutation RawShake256()
		{
			return new RawShakePermutation(512);
		}

		protected override BitString Suffix()
		{
			return new BitString("11");
		}
	}
}
