namespace AaronLuna.Crypto.SHA3
{
	public struct SpongeBit
	{
		public readonly SpongeState State;
		public readonly int X;
		public readonly int Y;
		public readonly int Z;

		public bool Value => State[State.GetIndex(this)];

	    internal SpongeBit(SpongeState state, int x, int y, int z)
	    {
			State = state;
			X = x;
			Y = y;
			Z = z;
		}

		public static bool operator true(SpongeBit spongeBit)
		{
			return spongeBit.Value;
		}

		public static bool operator false(SpongeBit spongeBit)
		{
			return !spongeBit.Value;
		}

		public static implicit operator bool(SpongeBit spongeBit)
		{
			return spongeBit.Value;
		}

		public override string ToString()
		{
			return $"Bit (X={X}, Y={Y}, Z={Z}) : {Value}";
		}
	}
}
