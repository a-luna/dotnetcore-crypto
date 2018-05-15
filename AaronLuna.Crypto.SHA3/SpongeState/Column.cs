namespace AaronLuna.Crypto.SHA3
{
    using System.Collections.Generic;

    public struct Column
	{
		public readonly SpongeState State;
		public readonly int X;
		public readonly int Z;

		internal Column(SpongeState state, int x, int z)
		{
			State = state;
			X = x;
			Z = z;
		}

		public IEnumerable<bool> GetBits()
		{
			for (var y = 0; y < 5; y++)
			{
				yield return State[State.GetIndex(X, y, Z)];
			}
		}

		public override string ToString()
		{
			return $"Column (X={X}, Z={Z})";
		}
	}
}
