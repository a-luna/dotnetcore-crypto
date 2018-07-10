namespace AaronLuna.Crypto.SHA3
{
	using System;
	using System.Collections;
	using System.Collections.Generic;
	using System.Linq;
	using System.Text;
	using System.Text.RegularExpressions;

	public sealed class BitString : IEquatable<BitString>, IEnumerable<bool>
	{
		public const int BlockBitSize = 8;
		public const int BlockByteSize = BlockBitSize >> Shift;
		public const int Shift = 3;

		static readonly Regex BitstringRegex
			= new Regex(@"^[01\s]*$", RegexOptions.Compiled | RegexOptions.CultureInvariant);

		byte[] _data;
		int _length;

		public static BitString One => new BitString("1", 1);
		public static BitString Zero => new BitString("0", 1);

		public int BlockCount => _data.Length;
		public byte[] Bytes => _data;
		public int Length => _length;

		public bool this[int index]
		{
			get
			{
				if (index < 0 || index >= _length)
				{
					throw new ArgumentOutOfRangeException(nameof(index));
				}

				var blockIndex = index >> Shift;
				var bitOffset = index % BlockBitSize;
				var chunk = _data[blockIndex];
				var mask = (byte)(1 << bitOffset);

				return (chunk & mask) == mask;
			}

			set
			{
				if (index < 0 || index >= _length)
				{
					throw new ArgumentOutOfRangeException(nameof(index));
				}

				var blockIndex = index >> Shift;
				var bitOffset = index % BlockBitSize;
				var mask = (byte)(1 << bitOffset);

				if (value)
				{
					_data[blockIndex] |= mask;
				}
				else
				{
					_data[blockIndex] &= (byte)(~mask & 0xFF);
				}
			}
		}

		public BitString() : this(0) { }

		public BitString(int length)
		{
			if (length < 0)
			{
				throw new ArgumentOutOfRangeException(nameof(length));
			}

			_length = length;
			_data = new byte[(int)Math.Ceiling((double)_length / BlockBitSize)];
		}

		public BitString(BitString bitString)
		{
			bitString = bitString ?? throw new ArgumentNullException(nameof(bitString));
			_data = new byte[bitString.BlockCount];
			Array.Copy(bitString._data, 0, _data, 0, bitString.BlockCount);
			_length = bitString._length;
		}

		public BitString(IEnumerable<bool> bits)
		{
			bits = bits ?? throw new ArgumentNullException(nameof(bits));
			_data = Parse(bits, out _length);
		}

		public BitString(string bits, int length = -1)
		{
			if (ValidateAndSanitize(ref bits, ref length))
			{
				var count = (int)Math.Ceiling((double)length / BlockBitSize);
				_data = new byte[count];
				var left = bits.Length;
				int i;

				// Stop the loop either when there is less than 8 bits to parse, or when desired length exceeds the size of
				// specified string.
				for (i = 0; left >= BlockBitSize && i << Shift < length; i++)
				{
					_data[i] = ParseByte(bits.Substring(i << Shift, BlockBitSize));
					left -= BlockBitSize;
				}
				if (left > 0)
				{
					_data[i] = ParseByte(bits.Substring(i << Shift, left));
				}

				_length = length;
			}
			else
			{
				throw new ArgumentException("Invalid bitString representation.", nameof(bits));
			}
		}

		public BitString(byte[] data, int length = -1)
		{
			data = data ?? throw new ArgumentNullException(nameof(data));
			var count = data.Length;
			var bitCount = count << Shift;

			_length = length < 0
				? bitCount
				: length;

			if (_length > bitCount)
			{
				throw new ArgumentOutOfRangeException(nameof(length));
			}

			// If the full range of bits is to be considered, whole process is a lot simpler.
			if (_length != bitCount)
			{
				// How many blocks will we need?
				count = (int)Math.Ceiling((double)_length / BlockBitSize);
				Array.Resize(ref data, count);

				// If the last block is not full, zero the trailing bits which do not belong to the bitString.
				var remaining = _length % BlockBitSize;
				if (remaining > 0)
				{
					data[count - 1] &= BinaryFunctions.LowerMask(remaining);
				}
			}
			_data = data;
		}

		public static bool operator == (BitString lhs, BitString rhs) =>
			ReferenceEquals(lhs, rhs) || !ReferenceEquals(lhs, null) && lhs.Equals(rhs);

		public static bool operator != (BitString lhs, BitString rhs) =>
			!ReferenceEquals(lhs, rhs) && (ReferenceEquals(lhs, null) || !lhs.Equals(rhs));

		public static BitString Ones(int length) =>
			length > 0
				? new BitString(new string('1', length))
				: new BitString();

		public static BitString Zeroes(int length) =>
			length > 0
				? new BitString(length)
				: new BitString();

		public static BitString Random(Random random, int length)
		{
			var count = (int)Math.Ceiling((double)length / BlockBitSize);
			var data = new byte[count];
			random.NextBytes(data);

			var left = length % BlockBitSize;
			if (left != 0)
			{
				data[count - 1] &= BinaryFunctions.LowerMask(left);
			}

			return new BitString(data, length);
		}

		public BitString And(BitString other) =>
			other.Length == _length
				? And(other._data)
				: this;

		public BitString And(byte[] data)
		{
			var count = BlockCount;
			if (data == null || data.Length != count) return this;

			for (var i = 0; i < count; i++)
			{
				_data[i] &= data[i];
			}

			return this;
		}

		public BitString Append(byte[] bytes)
		{
			if (bytes == null) return this;

			if (_length % BlockBitSize == 0)
			{
				// Array copy if aligned data
				var count = bytes.Length;
				var oldCount = BlockCount;
				Array.Resize(ref _data, oldCount + count);
				Array.Copy(bytes, 0, _data, oldCount, count);
				_length += count << Shift;
			}
			else
			{
				// Enumeration if unaligned data
				return Append(new BitString(bytes));
			}
			return this;
		}

		public BitString Append(IEnumerable<bool> bits)
		{
			var bitList = bits.ToList();
			if (bitList.Count <= 0) return this;

			var blockIndex = _length >> Shift;
			var bitOffset = _length % BlockBitSize;
			_length += bitList.Count;

			var newBlockCount = (int)Math.Ceiling((double)_length / BlockBitSize);
			if (newBlockCount > BlockCount)
			{
				Array.Resize(ref _data, newBlockCount);
			}

			foreach (var bit in bitList)
			{
				if (bit)
				{
					_data[blockIndex] |= (byte)(1 << bitOffset);
				}

				if (++bitOffset <= 7) continue;
				bitOffset = 0;
				blockIndex++;
			}

			return this;
		}

		public void Clear()
		{
			var count = BlockCount;
			for (var i = 0; i < count; i++)
			{
				_data[i] = 0;
			}
		}

		public bool Equals(BitString other)
		{
			if (other is null)
			{
				return false;
			}

			if (ReferenceEquals(this, other))
			{
				return true;
			}

			return _length == other._length && _data.SequenceEqual(other._data);
		}

		public override bool Equals(object obj) => obj is BitString bitstring && Equals(bitstring);

		public IEnumerator<bool> GetEnumerator() => GetBits().GetEnumerator();
		IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

		public override int GetHashCode() =>
			HashCoder<int>.Boost.Compute(_length, HashCoder<byte>.Boost.Compute(_data));

		public bool IsValidIndex(int index) => index > -1 && index < _length;

		public BitString Or(BitString other) =>
			other.Length == _length
				? Or(other._data)
				: this;

		public BitString Or(byte[] data)
		{
			if (data == null || data.Length != BlockCount) return this;

			for (var i = 0; i < BlockCount; i++)
			{
				_data[i] |= data[i];
			}

			return this;
		}

		public BitString Prepend(byte[] bytes)
		{
			if (bytes == null) return this;
			var count = bytes.Length;
			var oldCount = BlockCount;

			Array.Resize(ref _data, oldCount + count);
			Array.Copy(_data, 0, _data, count, oldCount);
			Array.Copy(bytes, 0, _data, 0, count);
			_length += count << Shift;

			return this;
		}

		public BitString Prepend(IEnumerable<bool> bits)
		{
			var copy = new BitString(this);
			var bitList = bits.ToList();

			if (bitList.Count <= 0) return this;
			_length += bitList.Count;

			var newBlockCount = (int)Math.Ceiling((double)_length / BlockBitSize);
			if (newBlockCount > BlockCount)
			{
				Array.Resize(ref _data, newBlockCount);
			}

			var blockIndex = 0;
			var bitOffset = 0;
			foreach (var bit in bitList)
			{
				if (bit)
				{
					_data[blockIndex] |= (byte)(1 << bitOffset);
				}
				else
				{
					_data[blockIndex] &= (byte)~(1 << bitOffset);
				}

				if (++bitOffset <= 7) continue;
				bitOffset = 0;
				blockIndex++;
			}

			foreach (var bit in copy)
			{
				if (bit)
				{
					_data[blockIndex] |= (byte)(1 << bitOffset);
				}
				else
				{
					_data[blockIndex] &= (byte)~(1 << bitOffset);
				}

				if (++bitOffset <= 7) continue;
				bitOffset = 0;
				blockIndex++;
			}

			return this;
		}

		public BitString Substring(int index, int length)
		{
			if (!IsValidIndex(index))
			{
				throw new ArgumentOutOfRangeException(nameof(index));
			}

			if (index % BlockBitSize != 0 || length % BlockBitSize != 0)
			{
				return new BitString(this.Skip(index).Take(length));
			}

			var count = length >> Shift;
			var data = new byte[count];
			Array.Copy(_data, index >> Shift, data, 0, count);

			return new BitString(data);
		}

		public BitString SwapBits(int lhs, int rhs)
		{
			if (!IsValidIndex(lhs) || !IsValidIndex(rhs) || lhs == rhs) return this;

			// The bit values at the specified locations are swapped without introducing
			// a temporary variable by performing the following bitwise opertions:
			// 1. l = l | r
			// 2. r = r | l
			// 3. l = l | r
			this[lhs] ^= this[rhs];
			this[rhs] ^= this[lhs];
			this[lhs] ^= this[rhs];
			return this;
		}

		public string ToBinString(int spacing = 0)
		{
			spacing = Math.Max(0, spacing);
			var numSpaces = spacing > 0
				? (int) Math.Ceiling((double) _length / spacing) - 1
				: 0;

			var length = _length + numSpaces;
			var builder = new StringBuilder(length);

			var i = 0;
			for (; i < BlockCount - 1; i++)
			{
				PrintByte(builder, _data[i]);
			}

			var numRemainingBits = _length % BlockBitSize;
			var finalBlockLength = numRemainingBits == 0
				? 8
				: numRemainingBits;

			PrintByte(builder, _data[i], finalBlockLength);

			if (spacing > 0)
			{
				AddSpacing(builder, spacing);
			}

			return builder.ToString();
		}

		public string ToHexString(bool spacing = true, bool uppercase = true)
		{
			var count = BlockCount << 1;
			var last = BlockCount - 1;
			var length = count + (spacing ? last : 0);
			var strFormat = uppercase ? "X2" : "x2";
			var builder = new StringBuilder(length);

			count >>= 1;
			for (var i = 0; i < count; i++)
			{
				builder.Append(_data[i].ToString(strFormat));
				if (spacing && i < last)
				{
					builder.Append(' ');
				}
			}

			return builder.ToString();
		}

		public override string ToString()
		{
			return $"({_length}) {ToHexString()}";
		}

		public BitString Truncate(int length)
		{
			length = Math.Min(_length, Math.Max(0, length));
			var count = (int)Math.Ceiling((double)length / BlockBitSize);
			var data = new byte[count];
			Array.Copy(_data, 0, data, 0, count);

			var left = length % BlockBitSize;
			if (left != 0)
			{
				data[count - 1] &= BinaryFunctions.LowerMask(left);
			}

			return new BitString(data, length);
		}

		public BitString Xor(BitString other)
		{
			return other.Length == _length
				? Xor(other._data)
				: this;
		}

		public BitString Xor(byte[] data)
		{
			var count = BlockCount;
			if (data == null || data.Length != count) return this;

			for (var i = 0; i < count; i++)
			{
				_data[i] ^= data[i];
			}

			return this;
		}

		static void AddSpacing(StringBuilder builder, int spacing)
		{
			var index = spacing;
			while (index < builder.Length)
			{
				builder.Insert(index, ' ');
				index += spacing + 1;
			}
		}

		IEnumerable<bool> GetBits()
		{
			for (var i = 0; i < _length; i++)
			{
				yield return this[i];
			}
		}

		static byte[] Parse(IEnumerable<bool> bits, out int length)
		{
			var bytes = new List<byte>(200);
			byte value = 0;
			var index = 0;
			var add = true;
			length = 0;

			foreach (var bit in bits)
			{
				length++;
				if (bit)
				{
					value |= (byte)(1 << index);
				}

				if (++index > 7)
				{
					index = 0;
					bytes.Add(value);
					value = 0;
					add = false;
				}
				else if (!add)
				{
					add = true;
				}
			}

			if (add)
			{
				bytes.Add(value);
			}

			return bytes.ToArray();
		}

		static byte ParseByte(string chunk)
		{
			byte result = 0;
			var length = chunk.Length;

			for (var i = 0; i < length; i++)
			{
				if (chunk[i] == '1')
				{
					result |= (byte)(1 << i);
				}
			}

			return result;
		}

		static void PrintByte(StringBuilder builder, byte value, int length = 8)
		{
			length = Math.Max(0, Math.Min(8, length));
			for (var i = 0; i < length; i++)
			{
				var bitString = (value & (1 << i)) != 0
					? '1'
					: '0';

				builder.Append(bitString);
			}
		}

		static bool ValidateAndSanitize(ref string bits, ref int length)
		{
			return ValidateBits(ref bits) && ValidateLength(ref length, bits.Length);
		}

		static bool ValidateBits(ref string bits)
		{
			var ok = (bits != null);
			if (!ok) return false;

			ok = BitstringRegex.IsMatch(bits);
			if (ok && bits.Contains(" "))
			{
				bits = bits.Replace(" ", "");
			}

			return ok;
		}

		static bool ValidateLength(ref int length, int stringLength)
		{
			if (length < 0)
			{
				length = stringLength;
			}

			return true;
		}
	}
}
