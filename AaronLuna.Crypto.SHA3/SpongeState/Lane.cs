namespace AaronLuna.Crypto.SHA3
{
    using System.Collections.Generic;

    public struct Lane
	{
		public readonly SpongeState State;
		public readonly int X;
		public readonly int Y;

		public int Depth => State.Size.W;

	    internal Lane(SpongeState state, int x, int y)
	    {
			State = state;
			X = x;
			Y = y;
		}

		public IEnumerable<bool> GetBits()
		{
			var w = State.Size.W;
			for (var z = 0; z < w; z++)
			{
				yield return State[State.GetIndex(X, Y, z)];
			}
		}

		public override string ToString()
		{
			return $"Lane (X={X}, Y={Y})";
		}
	}
}
