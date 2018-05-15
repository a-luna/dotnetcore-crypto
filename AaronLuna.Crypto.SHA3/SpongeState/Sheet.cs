namespace AaronLuna.Crypto.SHA3
{
    using System.Collections.Generic;

    public struct Sheet
	{
		public readonly SpongeState State;
		public readonly int X;

		public int Depth => State.Size.W;

	    internal Sheet(SpongeState state, int x)
	    {
			State = state;
			X = x;
		}

		public IEnumerable<Column> GetColumns()
		{
			var w = State.Size.W;
			for (var z = 0; z < w; z++)
			{
				yield return new Column(State, X, z);
			}
		}

		public IEnumerable<Lane> GetLanes()
		{
			for (var y = 0; y < 5; y++)
			{
				yield return new Lane(State, X, y);
			}
		}

		public override string ToString()
		{
			return $"Sheet (X={X})";
		}
	}
}
