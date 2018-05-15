namespace AaronLuna.Crypto.SHA3
{
    using System;
    using System.Collections.Generic;
    using System.Linq;

    public class KeccakPermutation : SpongeConstruction
	{
		struct RoundT : IEquatable<RoundT>
		{
		    readonly int _round;
		    readonly int _t;

			public RoundT(int round, int t) {
				_round = round;
				_t = t;
			}

			public static bool operator ==(RoundT lhs, RoundT rhs) => lhs.Equals(rhs);
		    public static bool operator !=(RoundT lhs, RoundT rhs) => !lhs.Equals(rhs);

		    public bool Equals(RoundT other) => _round == other._round && _t == other._t;
            public override bool Equals(object obj) => obj is RoundT && Equals((RoundT)obj);

            public override int GetHashCode() => HashCoder<int>.Boost.Compute(_round, _t);
		}

	    static readonly Dictionary<int, bool> RoundConstants =
	        new Dictionary<int, bool> {{0, true}};

	    static readonly Dictionary<RoundT, bool> RoundTConstants =
	        new Dictionary<RoundT, bool>();

        public int RoundCount { get; }

        protected KeccakPermutation(SpongeSize size, int rate, int roundCount) : base(size, rate)
        {
			RoundCount = roundCount;
		}

		protected override void Function()
		{
			var start = 12 + (State.Size.L << 1);
			for (var round = start - RoundCount; round < start; round++)
			{
				Iota(Khi(Pi(Rho(Theta(State)))), round);
			}
		}

		protected override BitString GetPadding(int r, int m)
		{
			var j = BinaryFunctions.Mod(-m - 2, r);
			var pad = new BitString(j + 2);
			pad[0] = true;
			pad[pad.Length - 1] = true;
			return pad;
		}

		static SpongeState Theta(SpongeState state)
		{
			var w = state.Size.W;
			var c = new bool[5, w];
			for (var x = 0; x < 5; x++)
			{
				for (var z = 0; z < w; z++)
				{
					c[x, z] =
					    state.GetColumn(x, z).GetBits().Aggregate((lhs, rhs) => lhs ^ rhs);
				}
			}

			var d = new bool[5, w];
			for (var x = 0; x < 5; x++)
			{
				for (var z = 0; z < w; z++)
				{
					d[x, z] =
					    c[BinaryFunctions.Mod(x - 1, 5), z] ^ c[BinaryFunctions.Mod(x + 1, 5),
					        BinaryFunctions.Mod(z - 1, w)];
				}
			}

			for (var x = 0; x < 5; x++)
			{
				for (var z = 0; z < w; z++)
				{
					var bit = d[x, z];
					for (var y = 0; y < 5; y++)
					{
						state[x, y, z] ^= bit;
					}
				}
			}

			return state;
		}

		static SpongeState Rho(SpongeState state)
		{
			var newState = new SpongeState(state.Size, state.Rate);
			var w = state.Size.W;
			newState.SetLane(newState.GetLane(0, 0), state.GetLane(0, 0).GetBits());

			var x = 1;
			var y = 0;
		    for (var t = 0; t < 24; t++)
		    {
				var u = ((t + 1) * (t + 2)) >> 1;
				for (var z = 0; z < w; z++)
				{
					newState[x, y, z] = state[x, y, BinaryFunctions.Mod(z - u, w)];
				}

				var oldX = x;
				x = y;
				y = BinaryFunctions.Mod(2 * oldX + 3 * y, 5);
			}

			state.SetBitString(newState.BitString);
			return state;
		}

		static SpongeState Pi(SpongeState state)
		{
			var newState = new SpongeState(state.Size, state.Rate);
			var w = state.Size.W;

			for (var y = 0; y < 5; y++)
			{
				for (var x = 0; x < 5; x++)
				{
					for (var z = 0; z < w; z++)
					{
						newState[x, y, z] = state[BinaryFunctions.Mod(x + 3 * y, 5), x, z];
					}
				}
			}

			state.SetBitString(newState.BitString);
			return state;
		}

		static SpongeState Khi(SpongeState state)
		{
			var newState = new SpongeState(state.Size, state.Rate);
			var w = state.Size.W;

			for (var y = 0; y < 5; y++)
			{
				for (var x = 0; x < 5; x++)
				{
					for (var z = 0; z < w; z++)
					{
						newState[x, y, z] =
                            state[x, y, z]
                                ^ (state[BinaryFunctions.Mod(x + 1, 5), y, z]
                                ^ true && state[BinaryFunctions.Mod(x + 2, 5),
                            y,
                            z]);
					}
				}
			}

			state.SetBitString(newState.BitString);
			return state;
		}

		static SpongeState Iota(SpongeState state, int round)
		{
			var w = state.Size.W;
			var l = state.Size.L;
			var rc = BitString.Zeroes(w);
		    int t;
			var rnd = 7 * round;

			for (var j = 0; j <= l; j++)
			{
				t = j + rnd;
				var roundT = new RoundT(round, t);
				if (!RoundTConstants.ContainsKey(roundT))
				{
					RoundTConstants.Add(roundT, RoundConstant(t));
				}

				rc[(1 << j) - 1] = RoundTConstants[roundT];
			}

			state.XorLane(state.GetLane(0, 0), rc);
			return state;
		}

		static bool RoundConstant(int t)
		{
			t = BinaryFunctions.Mod(t, 255);
			if (RoundConstants.ContainsKey(t))
			{
				return RoundConstants[t];
			}

			var r = new BitString("10000000", 8);
			for (var i = 0; i < t; i++)
			{
				r.Prepend(BitString.Zero);
				r[0] ^= r[8];
				r[4] ^= r[8];
				r[5] ^= r[8];
				r[6] ^= r[8];
				r = r.Truncate(8);
			}

			var bit = r[0];
			RoundConstants.Add(t, bit);

			return bit;
		}
	}
}
