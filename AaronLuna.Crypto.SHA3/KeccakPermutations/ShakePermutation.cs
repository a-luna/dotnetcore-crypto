namespace AaronLuna.Crypto.SHA3
{
	public sealed class ShakePermutation : Keccak
	{
		ShakePermutation(int capacity)
			: base(capacity) { }

		public static ShakePermutation Shake128()
		{
			return new ShakePermutation(256);
		}

		public static ShakePermutation Shake256()
		{
			return new ShakePermutation(512);
		}

		protected override BitString Suffix()
		{
			return new BitString("1111");
		}
	}
}
