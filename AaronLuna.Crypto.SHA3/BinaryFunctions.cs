namespace AaronLuna.Crypto.SHA3
{
    using System;

    public static class BinaryFunctions
	{
		static readonly int[] B = { 2, 12, 240, 65280, -65536 };
		static readonly int[] S = { 1, 2, 4, 8, 16 };

	    public static int Log2(int value)
		{
			var log = 0;

			for (var i = 4; i > -1; i--)
			{
			    if ((value & B[i]) == 0) continue;

			    value >>= S[i];
			    log |= S[i];
			}

			return log;
		}

		public static byte LowerMask(int count)
		{
			byte value = 0;
		    if (count <= 0) return value;

		    count %= 8;
		    if (count == 0)
		    {
		        value = 255;
		    }
		    else
		    {
		        for (var i = 0; i < count; i++)
		        {
		            value |= (byte)(1 << i);
		        }
		    }
		    return value;
		}

		public static int Mod(int value, int mod)
		{
			return value - mod * (int)Math.Floor((double)value / mod);
		}
	}
}
