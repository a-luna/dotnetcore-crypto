namespace AaronLuna.Crypto.SHA3
{
    using System.Collections.Generic;

    public struct Slice
	{
		public readonly SpongeState State;
		public readonly int Z;

		internal Slice(SpongeState state, int z)
		{
			State = state;
			Z = z;
		}

		public IEnumerable<Column> GetColumns()
		{
			for (var x = 0; x < 5; x++)
			{
				yield return new Column(State, x, Z);
			}
		}

		public IEnumerable<Row> GetRows()
		{
			for (var y = 0; y < 5; y++)
			{
				yield return new Row(State, y, Z);
			}
		}

		public override string ToString()
		{
			return $"Slice (Z={Z})";
		}
	}
}
