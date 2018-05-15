namespace AaronLuna.Crypto.SHA3
{
    using System.Collections.Generic;
    using System.Linq;

    public interface IHashCoder<T>
	{
		int Compute(IEnumerable<T> values);
		int Compute(params T[] values);
	}

	public abstract class HashCoder<T> : IHashCoder<T>
	{
		public static IHashCoder<T> Boost => BoostHashCoder<T>.Instance;
		public static IHashCoder<T> Default => DefaultHashCoder<T>.Instance;

		public abstract int Compute(IEnumerable<T> values);

		public int Compute(params T[] values)
		{
			return Compute(values.AsEnumerable());
		}
	}

	public sealed class DefaultHashCoder<T> : HashCoder<T>
	{
		class Singleton
		{
			internal static readonly DefaultHashCoder<T> Instance = new DefaultHashCoder<T>();
			static Singleton() { }
		}

		public static DefaultHashCoder<T> Instance => Singleton.Instance;

	    DefaultHashCoder() { }

		public override int Compute(IEnumerable<T> values)
		{
			var hash = 27;
			foreach (var value in values)
			{
				hash *= 13;
				hash += value.GetHashCode();
			}
			return hash;
		}
	}

	public sealed class BoostHashCoder<T> : HashCoder<T>
	{
		class Singleton
		{
			internal static readonly BoostHashCoder<T> Instance = new BoostHashCoder<T>();
			static Singleton() { }
		}

		public static BoostHashCoder<T> Instance => Singleton.Instance;

	    BoostHashCoder() { }

		static void Combine(ref int seed, T value)
		{
		    unchecked
		    {
		        seed ^= value.GetHashCode() + (int)0x9e3779b9 + (seed << 6) + (seed >> 2);
		    }
		}

		public override int Compute(IEnumerable<T> values)
		{
			var hash = 0;
			foreach (var value in values)
			{
				Combine(ref hash, value);
			}

			return hash;
		}
	}
}
