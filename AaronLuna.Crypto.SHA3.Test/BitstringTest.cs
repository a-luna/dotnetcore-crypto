namespace AaronLuna.Crypto.SHA3.Test
{
    using System;
    using System.Collections.Generic;
    using System.Linq;

    using Microsoft.VisualStudio.TestTools.UnitTesting;

    using SHA3;

    [TestClass]
	public class BitStringTest
	{
		const string Category = "BitString";

		[TestMethod, TestCategory(Category)]
		public void One_ShouldReturnExpectedBitstring()
		{
			var bitString = BitString.One;
			Assert.AreEqual(1, bitString.Length);
			Assert.AreEqual("1", bitString.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void Zero_ShouldReturnExpectedBitstring()
		{
			var bitString = BitString.Zero;
			Assert.AreEqual(1, bitString.Length);
			Assert.AreEqual("0", bitString.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void BlockCount_ShouldReturnExpectedValue()
		{
			var bitString = new BitString("100101101110");
			Assert.AreEqual(2, bitString.BlockCount);
		}

		[TestMethod, TestCategory(Category)]
		public void Bytes_ShouldReturnExpectedValue()
		{
			var bitString = new BitString("1010010101000010");
			Assert.IsTrue(new byte[] { 0xA5, 0x42 }.SequenceEqual(bitString.Bytes));
		}

		[TestMethod, TestCategory(Category)]
		public void ItemAccessor_Getter_ShouldGetSpecifiedBit()
		{
			var bitString = new BitString("11001");
			Assert.IsTrue(bitString[0]);
			Assert.IsTrue(bitString[1]);
			Assert.IsFalse(bitString[2]);
			Assert.IsFalse(bitString[3]);
			Assert.IsTrue(bitString[4]);
		}

		[TestMethod, TestCategory(Category)]
		public void ItemAccessor_Setter_ShouldSetSpecifiedBit()
		{
		    var bitString = new BitString("11001")
		    {
		        [1] = false,
		        [2] = true
		    };

		    Assert.AreEqual("10101", bitString.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void Length_ShouldReturnExpectedValue()
		{
			var bitString = new BitString("11001");
			Assert.AreEqual(5, bitString.Length);
		}

		[TestMethod, TestCategory(Category)]
		public void Constructor_Bitstring_ShouldCopy()
		{
			var source = new BitString("11001001");
			var bitString = new BitString(source);
			Assert.AreNotSame(source, bitString);
			Assert.AreEqual(source, bitString);
		}

		[TestMethod, TestCategory(Category), ExpectedException(typeof(ArgumentNullException))]
		public void Constructor_Bitstring_ShouldThrow_WhenNullBitstring()
        {
			BitString source = null;
			var bitString = new BitString(source);
		}

		[TestMethod, TestCategory(Category)]
		public void Constructor_ByteArray_ShouldCreateCorrectBitstring()
		{
			var data = new byte[] { 0x06, 0x80 };
			var bitString = new BitString(data);
			Assert.AreEqual(16, bitString.Length);
			Assert.AreEqual(2, bitString.BlockCount);
			Assert.AreEqual("0110000000000001", bitString.ToBinString());
		}

		[TestMethod, TestCategory(Category), ExpectedException(typeof(ArgumentNullException))]
		public void Constructor_ByteArray_ShouldThrow_WhenNullArray()
		{
			byte[] data = null;
			var bitString = new BitString(data);
		}

		[TestMethod, TestCategory(Category)]
		public void Constructor_ByteArrayLength_ShouldCreateCorrectBitstring()
		{
			var data = new byte[] { 0x45, 0x3C };
			var bitString = new BitString(data, 14);
			Assert.AreEqual(14, bitString.Length);
			Assert.AreEqual(2, bitString.BlockCount);
			Assert.AreEqual("10100010001111", bitString.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void Constructor_ByteArrayLength_ShouldTrim_WhenNeeded()
		{
			var data = new byte[] { 0x45, 0x3C };
			var bitString = new BitString(data, 7);
			Assert.AreEqual(7, bitString.Length);
			Assert.AreEqual(1, bitString.BlockCount);
			Assert.AreEqual("1010001", bitString.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void Constructor_Empty_ShouldCreateEmptyBistring()
		{
			var bitString = new BitString();
			Assert.AreEqual(0, bitString.Length);
			Assert.AreEqual(0, bitString.BlockCount);
		}

		[TestMethod, TestCategory(Category)]
		public void Constructor_IEnumerableBool_ShouldCreateCorrectBitstring()
		{
			var bits = new bool[] { true, true, false, false, true };
			var bitString = new BitString(bits);
			Assert.AreEqual(5, bitString.Length);
			Assert.AreEqual("11001", bitString.ToBinString());
		}

		[TestMethod, TestCategory(Category), ExpectedException(typeof(ArgumentNullException))]
		public void Constructor_IEnumerableBool_ShouldThrow_WhenNullBits()
		{
			IEnumerable<bool> bits = null;
			var bitString = new BitString(bits);
		}

		[TestMethod, TestCategory(Category)]
		public void Constructor_Length_ShouldCreateExpectedBitstring()
		{
			var bitString = new BitString(14);
			Assert.AreEqual(14, bitString.Length);
			for (var i = 0; i < 14; i++)
			{
				Assert.IsFalse(bitString[i]);
			}
		}

		[TestMethod, TestCategory(Category), ExpectedException(typeof(ArgumentOutOfRangeException))]
		public void Constructor_Length_ShouldThrow_WhenNegativeLength()
		{
			var bitString = new BitString(-1);
		}

		[TestMethod, TestCategory(Category)]
		public void Constructor_String_ShouldAcceptBinaryStringsWithWhitespaces()
		{
			var bits = " 1 1 0 0 1 0 0 1 ";
			var bitString = new BitString(bits);
			Assert.AreEqual(8, bitString.Length);
			Assert.AreEqual("11001001", bitString.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void Constructor_String_ShouldCreateExpetcedBitstring()
		{
			var bitString = new BitString("11001010");
			Assert.AreEqual(8, bitString.Length);
			Assert.AreEqual(1, bitString.BlockCount);
			Assert.AreEqual(true, bitString[0]);
			Assert.AreEqual(true, bitString[1]);
			Assert.AreEqual(false, bitString[2]);
			Assert.AreEqual(false, bitString[3]);
			Assert.AreEqual(true, bitString[4]);
			Assert.AreEqual(false, bitString[5]);
			Assert.AreEqual(true, bitString[6]);
			Assert.AreEqual(false, bitString[7]);
		}

		[TestMethod, TestCategory(Category), ExpectedException(typeof(ArgumentException))]
		public void Constructor_String_ShouldThrow_WhenInvalidBinaryRepresentation()
		{
			var bits = "11a11";
			var bitString = new BitString(bits);
		}

		[TestMethod, TestCategory(Category), ExpectedException(typeof(ArgumentException))]
		public void Constructor_String_ShouldThrow_WhenNullBits()
		{
			string bits = null;
			var bitString = new BitString(bits);
		}

		[TestMethod, TestCategory(Category)]
		public void Constructor_StringInt_ShouldCreateCorrectBitstring()
		{
			var bitString = new BitString("11001010", 4);
			Assert.AreEqual(4, bitString.Length);
			Assert.AreEqual(1, bitString.BlockCount);
			Assert.AreEqual(true, bitString[0]);
			Assert.AreEqual(true, bitString[1]);
			Assert.AreEqual(false, bitString[2]);
			Assert.AreEqual(false, bitString[3]);
		}

		[TestMethod, TestCategory(Category)]
		public void EqualityOperator_ShouldReturnFalse_WhenDistinctLength()
		{
			var bitString = new BitString("10000");
			var other = new BitString("100000");
			Assert.IsTrue(Enumerable.SequenceEqual(bitString.Bytes, other.Bytes));
			Assert.IsFalse(bitString == other);
		}

		[TestMethod, TestCategory(Category)]
		public void EqualityOperator_ShouldReturnFalse_WhenNullLeft()
		{
			BitString bitString = null;
			var other = BitString.One;
			Assert.IsFalse(bitString == other);
		}

		[TestMethod, TestCategory(Category)]
		public void EqualityOperator_ShouldReturnTrue_WhenBothNull()
		{
			BitString bitString = null;
			BitString other = null;
			Assert.IsTrue(bitString == other);
		}

		[TestMethod, TestCategory(Category)]
		public void EqualityOperator_ShouldReturnTrue_WhenSameInstance()
		{
			var bitString = new BitString("11001");
			var other = bitString;
			Assert.IsTrue(bitString == other);
			Assert.AreSame(bitString, other);
		}

		[TestMethod, TestCategory(Category)]
		public void EqualityOperator_ShouldReturnTrue_WhenDistinctInstanceWithSameDataAndLength()
		{
			var bitString = new BitString("11001");
			var other = new BitString("11001");
			Assert.IsTrue(bitString == other);
			Assert.AreNotSame(bitString, other);
		}

		[TestMethod, TestCategory(Category)]
		public void InequalityOperator_ShouldReturnFalse_WhenBothNull()
		{
			BitString bitString = null;
			BitString other = null;
			Assert.IsFalse(bitString != other);
		}

		[TestMethod, TestCategory(Category)]
		public void InequalityOperator_ShouldReturnFalse_WhenSameInstance()
		{
			var bitString = new BitString("11001");
			var other = bitString;
			Assert.IsFalse(bitString != other);
			Assert.AreSame(bitString, other);
		}

		[TestMethod, TestCategory(Category)]
		public void InequalityOperator_ShouldReturnFalse_WhenDistinctInstanceWithSameDataAndLength()
		{
			var bitString = new BitString("11001");
			var other = new BitString("11001");
			Assert.IsFalse(bitString != other);
			Assert.AreNotSame(bitString, other);
		}

		[TestMethod, TestCategory(Category)]
		public void InequalityOperator_ShouldReturnTrue_WhenDistinctLength()
		{
			var bitString = new BitString("10000");
			var other = new BitString("100000");
			Assert.IsTrue(Enumerable.SequenceEqual(bitString.Bytes, other.Bytes));
			Assert.IsTrue(bitString != other);
		}

		[TestMethod, TestCategory(Category)]
		public void InequalityOperator_ShouldReturnTrue_WhenNullLeft()
		{
			BitString bitString = null;
			var other = BitString.One;
			Assert.IsTrue(bitString != other);
		}

		[TestMethod, TestCategory(Category)]
		public void Ones_ShouldReturnEmptyString_WhenNegativeLength()
		{
			var bitString = BitString.Ones(-2);
			Assert.AreEqual(new BitString(), bitString);
		}

		[TestMethod, TestCategory(Category)]
		public void Ones_ShouldReturnExpectedBitstring()
		{
			var bitString = BitString.Ones(5);
			Assert.AreEqual(5, bitString.Length);
			Assert.AreEqual("11111", bitString.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void Random_ShouldReturnDistinctBitstrings()
		{
			var random = new Random();
			var b1 = BitString.Random(random, 42);
			var b2 = BitString.Random(random, 42);
			Assert.AreNotEqual(b1, b2);
		}

		[TestMethod, TestCategory(Category)]
		public void Zeroes_ShouldReturnEmptyString_WhenNegativeLength()
		{
			var bitString = BitString.Zeroes(-2);
			Assert.AreEqual(new BitString(), bitString);
		}

		[TestMethod, TestCategory(Category)]
		public void Zeroes_ShouldReturnExpectedBitstring()
		{
			var bitString = BitString.Zeroes(7);
			Assert.AreEqual(7, bitString.Length);
			Assert.AreEqual("0000000", bitString.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void And_Bitstring_ShouldDoNothing_WhenNotSameLength()
		{
			var bitString = new BitString("10101010");
			var other = new BitString("1010");
			bitString.And(other);
			Assert.AreEqual("10101010", bitString.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void And_ByteArray_ShouldAndCurrentInstanceWithData()
		{
			var bitString = new BitString("10101010");
			var bytes = new byte[] { 195 }; // = "11000011"
			bitString.And(bytes);
			Assert.AreEqual("10000010", bitString.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void And_ByteArray_ShouldDoNothing_WhenNullData()
		{
			var bitString = new BitString("10101010");
			byte[] bytes = null;
			bitString.And(bytes);
			Assert.AreEqual("10101010", bitString.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void And_ByteArray_ShouldDoNothing_WhenNotSameLength()
		{
			var bitString = new BitString("10101010");
			var bytes = new byte[] { 0, 0 };
			bitString.And(bytes);
			Assert.AreEqual("10101010", bitString.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void Append_ByteArray_ShouldAppendData_WhenLastBlockFull()
		{
			var bitString = new BitString("10010110");
			bitString.Append(new byte[] { 0xA5 });
			Assert.AreEqual(16, bitString.Length);
			Assert.AreEqual("1001011010100101", bitString.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void Append_ByteArray_ShouldAppendData_WhenLastBlockNotFull()
		{
			var bitString = new BitString("100101");
			bitString.Append(new byte[] { 0xA5 });
			Assert.AreEqual(14, bitString.Length);
			Assert.AreEqual("10010110100101", bitString.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void Append_ByteArray_ShouldDoNothing_WhenNullData()
		{
			var bitString = new BitString("11001");
			byte[] data = null;
			bitString.Append(data);
			Assert.AreEqual(5, bitString.Length);
			Assert.AreEqual("11001", bitString.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void Clear_ShouldClearAndPreserveLength()
		{
			var bitString = new BitString("10010110");
			bitString.Clear();
			Assert.AreEqual(8, bitString.Length);
			Assert.AreEqual("00000000", bitString.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void Equals_Bitstring_ShouldReturnFalse_WhenNotEqual()
		{
			var bitString = new BitString("10010100");
			var other = new BitString("10010110");
			Assert.IsFalse(bitString.Equals(other));
		}

		[TestMethod, TestCategory(Category)]
		public void Equals_Bitstring_ShouldReturnFalse_WhenNotSameLength()
		{
			var bitString = new BitString("10010100");
			var other = new BitString("100101");
			Assert.IsTrue(Enumerable.SequenceEqual(bitString.Bytes, other.Bytes));
			Assert.IsFalse(bitString.Equals(other));
		}

		[TestMethod, TestCategory(Category)]
		public void Equals_Bitstring_ShouldReturnFalse_WhenNullOther()
		{
			var bitString = new BitString();
			BitString other = null;
			Assert.IsFalse(bitString.Equals(other));
		}

		[TestMethod, TestCategory(Category)]
		public void Equals_Bitstring_ShouldReturnTrue_WhenEqual()
		{
			var bitString = new BitString("10010110");
			var other = new BitString("10010110");
			Assert.AreNotSame(bitString, other);
			Assert.IsTrue(bitString.Equals(other));
		}

		[TestMethod, TestCategory(Category)]
		public void Equals_Bitstring_ShouldReturnTrue_WhenSameInstance()
		{
			var bitString = new BitString();
			var other = bitString;
			Assert.IsTrue(bitString.Equals(other));
		}

		[TestMethod, TestCategory(Category)]
		public void Equals_Object_ShouldReturnFalse_WhenNotBitstring()
		{
			var bitString = new BitString();
			var other = "";
			Assert.IsFalse(bitString.Equals(other));
		}

		[TestMethod, TestCategory(Category)]
		public void Equals_Object_ShouldReturnFalse_WhenNotEqual()
		{
			var bitString = new BitString("10010110");
			object other = new BitString("10010100");
			Assert.IsFalse(bitString.Equals(other));
		}

		[TestMethod, TestCategory(Category)]
		public void Equals_Object_ShouldReturnTrue_WhenEqual()
		{
			var bitString = new BitString("10010110");
			object other = new BitString("10010110");
			Assert.IsTrue(bitString.Equals(other));
		}

		[TestMethod, TestCategory(Category)]
		public void GetEnumerator_ShouldProvideBitEnumerator()
		{
			var bitString = new BitString("01010101");
			var i = 0;
			foreach (var bit in bitString)
			{
				if ((i++ & 1) == 0)
				{
					Assert.IsFalse(bit);
				}
				else
				{
					Assert.IsTrue(bit);
				}
			}
		}

		[TestMethod, TestCategory(Category)]
		public void GetHashCode_ShouldReturnDistinctHashCode_WhenDistinctLength()
		{
			var bitString = new BitString("11001100");
			var other = new BitString("110011");
			Assert.AreNotEqual(bitString.GetHashCode(), other.GetHashCode());
		}

		[TestMethod, TestCategory(Category)]
		public void GetHashCode_ShouldReturnSameHashCode_WhenEqual()
		{
			var bitString = new BitString("11001");
			var other = new BitString("11001");
			Assert.AreEqual(bitString.GetHashCode(), other.GetHashCode());
		}

		[TestMethod, TestCategory(Category)]
		public void Or_Bitstring_ShouldDoNothing_WhenNotSameLength()
		{
			var bitString = new BitString("10010110");
			var other = new BitString("1010");
			bitString.Or(other);
			Assert.AreEqual("10010110", bitString.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void Or_ByteArray_ShouldDoNothing_WhenNullData()
		{
			var bitString = new BitString("10101010");
			byte[] bytes = null;
			bitString.Or(bytes);
			Assert.AreEqual("10101010", bitString.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void Or_ByteArray_ShouldDoNothing_WhenNotSameLength()
		{
			var bitString = new BitString("10101010");
			var bytes = new byte[] { 0, 0 };
			bitString.Or(bytes);
			Assert.AreEqual("10101010", bitString.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void Or_ByteArray_ShouldOrCurrentInstanceWithData()
		{
			var bitString = new BitString("10101010");
			var bytes = new byte[] { 15 }; // = "00001111"
			bitString.Or(bytes);
			Assert.AreEqual("11111010", bitString.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void Prepend_Bitstring_ShouldPrependData_WhenLastBlockNotFull()
		{
			var bitString = new BitString("10010110");
			bitString.Prepend(new BitString("11011"));
			Assert.AreEqual(13, bitString.Length);
			Assert.AreEqual("1101110010110", bitString.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void Prepend_ByteArray_ShouldDoNothing_WhenNullData()
		{
			var bitString = new BitString("11001");
			byte[] data = null;
			bitString.Prepend(data);
			Assert.AreEqual(5, bitString.Length);
			Assert.AreEqual("11001", bitString.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void Prepend_ByteArray_ShouldPrependData_WhenLastBlockFull()
		{
			var bitString = new BitString("10010110");
			bitString.Prepend(new byte[] { 0xA5 });
			Assert.AreEqual(16, bitString.Length);
			Assert.AreEqual("1010010110010110", bitString.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void Substring_ShouldReturnExpectedSubstring_WithCopy()
		{
			var bitString = new BitString("111101011001011011100010");
			var other = bitString.Substring(8, 8);
			Assert.AreEqual(8, other.Length);
			Assert.AreEqual("10010110", other.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void Substring_ShouldReturnExpectedSubstring_WithEnumeration()
		{
			var bitString = new BitString("11110101");
			var other = bitString.Substring(3, 4);
			Assert.AreEqual(4, other.Length);
			Assert.AreEqual("1010", other.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void SwapBits_ShouldSwapBits()
		{
			var bitString = new BitString("11001");
			bitString.SwapBits(1, 2);
			Assert.AreEqual("10101", bitString.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void ToBinString_ShouldReturnExpectedString()
		{
			var bitString = new BitString("100101101100");
			Assert.AreEqual("100101101100", bitString.ToBinString());
			Assert.AreEqual("10 01 01 10 11 00", bitString.ToBinString(2));
			Assert.AreEqual("100 101 101 100", bitString.ToBinString(3));
			Assert.AreEqual("1001 0110 1100", bitString.ToBinString(4));
		}

		[TestMethod, TestCategory(Category)]
		public void ToHexString_ShouldReturnExpectedString()
		{
			var bitString = new BitString(new byte[] { 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78 });
			Assert.AreEqual("0F 1E 2D 3C 4B 5A 69 78", bitString.ToHexString());
			Assert.AreEqual("0F1E2D3C4B5A6978", bitString.ToHexString(false, true));
			Assert.AreEqual("0f 1e 2d 3c 4b 5a 69 78", bitString.ToHexString(true, false));
			Assert.AreEqual("0f1e2d3c4b5a6978", bitString.ToHexString(false, false));
		}

		[TestMethod, TestCategory(Category)]
		public void ToString_ShouldReturnExpectedString()
		{
			var bitString = new BitString("00111");
			Assert.AreEqual("(5) 1C", bitString.ToString());
		}

		[TestMethod, TestCategory(Category)]
		public void Truncate_ShouldReturnExpectedBitstring()
		{
			var bitString = new BitString("1100100101101010");
			var other = bitString.Truncate(7);
			Assert.AreEqual(7, other.Length);
			Assert.AreEqual("1100100", other.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void Xor_Bitstring_ShouldDoNothing_WhenNotSameLength()
		{
			var bitString = new BitString("10010110");
			var other = new BitString("1010");
			bitString.Xor(other);
			Assert.AreEqual("10010110", bitString.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void Xor_ByteArray_ShouldDoNothing_WhenNullData()
		{
			var bitString = new BitString("10101010");
			byte[] bytes = null;
			bitString.Xor(bytes);
			Assert.AreEqual("10101010", bitString.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void Xor_ByteArray_ShouldDoNothing_WhenNotSameLength()
		{
			var bitString = new BitString("10101010");
			var bytes = new byte[] { 0, 0 };
			bitString.Xor(bytes);
			Assert.AreEqual("10101010", bitString.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void Xor_ByteArray_ShouldXorCurrentInstanceWithData()
		{
			var bitString = new BitString("10101010");
			var bytes = new byte[] { 255 }; // = "11111111"
			bitString.Xor(bytes);
			Assert.AreEqual("01010101", bitString.ToBinString());
		}
	}
}
