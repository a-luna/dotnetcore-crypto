namespace AaronLuna.Crypto.SHA3
{
    using System.Collections.Generic;

    public struct Row
	{
		public readonly SpongeState State;
		public readonly int Y;
		public readonly int Z;

		internal Row(SpongeState state, int y, int z)
		{
			State = state;
			Y = y;
			Z = z;
		}

		public IEnumerable<bool> GetBits()
		{
			for (var x = 0; x < 5; x++)
			{
				yield return State[State.GetIndex(x, Y, Z)];
			}
		}

		public override string ToString()
		{
			return $"Row (Y={Y}, Z={Z})";
		}
	}
}
