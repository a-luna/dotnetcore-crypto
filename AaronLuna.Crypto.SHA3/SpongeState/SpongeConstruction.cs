namespace AaronLuna.Crypto.SHA3
{
	public interface ISpongeConstruction
	{
		int Capacity { get; }
		int Rate { get; }
		SpongeSize Size { get; }

		byte[] Process(byte[] bytes, int outputLength, int inputLength = -1);
	}

	public abstract class SpongeConstruction : ISpongeConstruction
	{
		protected readonly SpongeState State;

        public int Capacity => State.Capacity;
        public int Rate => State.Rate;
        public SpongeSize Size => State.Size;

        protected SpongeConstruction(SpongeSize size, int rate)
        {
			State = new SpongeState(size, rate);
		}

		protected virtual void Absorb(byte[] bytes, int length)
		{
			State.Clear();
			var message = new BitString(bytes, length);
			var rate = State.Rate;
			message.Append(Suffix());
			message.Append(GetPadding(rate, message.Length));

			var n = message.Length / rate;
			var zeroes = new BitString(Capacity);
			BitString chunk;
			for (var i = 0; i < n; i++)
			{
				chunk = message.Substring(rate * i, rate);
				chunk.Append(zeroes);
				State.BitString.Xor(chunk);
				Function();
			}
		}

		protected abstract void Function();
		protected abstract BitString GetPadding(int r, int m);

		public virtual byte[] Process(byte[] bytes, int outputLength, int inputLength = -1)
		{
			byte[] result = null;
			if (bytes != null)
			{
				inputLength =
				    (inputLength > -1)
				        ? inputLength
				        : bytes.Length << BitString.Shift;

				Absorb(bytes, inputLength);
				result = Squeeze(outputLength);
			}
			return result;
		}

		protected virtual byte[] Squeeze(int outputLength)
		{
			var rate = State.Rate;
			var q = new BitString();
			while (true)
			{
				q.Append(State.BitString.Truncate(rate));
				if (q.Length >= outputLength)
				{
					return (q.Length == outputLength)
					    ? q.Bytes
					    : q.Truncate(outputLength).Bytes;
				}

				Function();
			}
		}

		protected virtual BitString Suffix()
		{
			 return new BitString();
		}
	}
}
