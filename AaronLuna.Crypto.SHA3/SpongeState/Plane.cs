namespace AaronLuna.Crypto.SHA3
{
    using System.Collections.Generic;

    public struct Plane
	{
	    public readonly SpongeState State;
		public readonly int Y;

		public int Depth => State.Size.W;

	    internal Plane(SpongeState state, int y)
	    {
			State = state;
			Y = y;
		}

		public IEnumerable<Lane> GetLanes()
		{
			for (var x = 0; x < 5; x++)
			{
				yield return new Lane(State, x, Y);
			}
		}

		public IEnumerable<Row> GetRows()
		{
			var w = State.Size.W;
			for (var z = 0; z < w; z++)
			{
				yield return new Row(State, Y, z);
			}
		}

		public override string ToString()
		{
			return $"Plane (Y={Y})";
		}
	}
}
