namespace AaronLuna.Crypto.SHA3
{
    using System;
    using System.Security.Cryptography;

    public sealed class Sha3HashAlgorithm : HashAlgorithm
	{
		public enum Size : byte
		{
			Bits224,
			Bits256,
			Bits384,
			Bits512
		}

		readonly Sha3Permutation _permutation;

		BitString _hash = new BitString();

		public Sha3HashAlgorithm(Size size)
		{
			switch (size) {

				case Size.Bits224:
					_permutation = Sha3Permutation.Sha3_224();
					break;

				case Size.Bits256:
					_permutation = Sha3Permutation.Sha3_256();
					break;

			    case Size.Bits384:
					_permutation = Sha3Permutation.Sha3_384();
					break;

			    default:
					_permutation = Sha3Permutation.Sha3_512();
					break;
			}
		}

		public static Sha3HashAlgorithm Create(Size size)
		{
			return new Sha3HashAlgorithm(size);
		}

		protected override void HashCore(byte[] array, int ibStart, int cbSize)
		{
			var data = new byte[cbSize];
			Array.Copy(array, ibStart, data, 0, cbSize);
			_hash.Append(data);
		}

		protected override byte[] HashFinal()
		{
			_hash = new BitString(_permutation.Process(_hash.Bytes, _permutation.Width));
			return _hash?.Bytes ?? Array.Empty<byte>();
		}

		public override void Initialize()
		{
			_hash = new BitString();
		}
	}
}
