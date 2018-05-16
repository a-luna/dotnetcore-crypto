namespace AaronLuna.Crypto.SHA3.Test
{
    using System;
    using System.Linq;

    using Microsoft.VisualStudio.TestTools.UnitTesting;

    using SHA3;

    [TestClass]
	public class SpongeStateTest
	{
		const string Category = "SpongeState";

		[TestMethod, TestCategory(Category)]
		public void Bitstring_Getter_ShouldReturnExpectedBitstring()
		{
			var state = new SpongeState(SpongeSize.W02, 32);
			Assert.AreEqual("00000000000000000000000000000000000000000000000000", state.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void Bitstring_Setter_ShouldSetBitstring_WhenCorrectSize()
		{
			var state = new SpongeState(SpongeSize.W02, 32);
			var bitString = new BitString("10101010101010101010101010101010101010101010101010");
			state.BitString = bitString;
			Assert.AreEqual("10101010101010101010101010101010101010101010101010", state.ToBinString());
		}

		[TestMethod, TestCategory(Category), ExpectedException(typeof(ArgumentException))]
		public void Bitstring_Setter_ShouldThrow_WhenIncorrectSize()
		{
			var state = new SpongeState(SpongeSize.W02, 32);
			var bitString = new BitString("101010101010101010101010101010101010101010101010");
			state.BitString = bitString;
		}

		[TestMethod, TestCategory(Category)]
		public void Capacity_Getter_ShouldReturnCorrectResult()
		{
			var state = new SpongeState(SpongeSize.W64, 1400);
			Assert.AreEqual(200, state.Capacity);
		}

		[TestMethod, TestCategory(Category)]
		public void ItemAccessor_3D_Getter_ShouldReturnExpectedBit()
		{
			var bitString = new BitString("10101010101010101010101010101010101010101010101010");
			var state = new SpongeState(bitString, 30);
			Assert.IsTrue(state[0, 0, 0]);

			for (var y = 0; y < 5; y++)
			{
				for (var x = 0; x < 5; x++)
				{
					for (var z = 0; z < 2; z++)
					{
						if ((z & 1) == 0)
						{
							Assert.IsTrue(state[x, y, z]);
						}
						else
						{
							Assert.IsFalse(state[x, y, z]);
						}
					}
				}
			}
		}

		[TestMethod, TestCategory(Category)]
		public void ItemAccessor_3D_Setter_ShouldSetExpectedBit()
		{
			var bitString = new BitString("10101010101010101010101010101010101010101010101010");
			var state = new SpongeState(bitString, 30);
			state[0, 0, 0] = false;
			state[0, 0, 1] = true;
			Assert.AreEqual("01101010101010101010101010101010101010101010101010", state.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void ItemAccessor_Flat_Getter_ShouldReturnExpectedBit()
		{
			var bitString = new BitString("10101010101010101010101010101010101010101010101010");
			var state = new SpongeState(bitString, 30);
			for (var i = 0; i < state.BitString.Length; i++)
			{
				if ((i & 1) == 0)
				{
					Assert.IsTrue(state[i]);
				}
				else
				{
					Assert.IsFalse(state[i]);
				}
			}
		}

		[TestMethod, TestCategory(Category)]
		public void ItemAccessor_Flat_Setter_ShouldSetExpectedBit()
		{
			var bitString = new BitString("10101010101010101010101010101010101010101010101010");
			var state = new SpongeState(bitString, 30);
			state[1] = true;
			Assert.IsTrue(state[1]);
		}

		[TestMethod, TestCategory(Category)]
		public void Rate_Getter_ShouldReturnCorrectResult()
		{
			var state = new SpongeState(SpongeSize.W64, 1400);
			Assert.AreEqual(1400, state.Rate);
		}

		[TestMethod, TestCategory(Category)]
		public void Size_Getter_ShouldReturnCorrectResult()
		{
			var state = new SpongeState(SpongeSize.W64, 1400);
			Assert.AreEqual(SpongeSize.W64, state.Size);
		}

		[TestMethod, TestCategory(Category)]
		public void Constructor_BitstringRate_ShouldCreateExpectedState()
		{
			var bitString = new BitString("10101010101010101010101010101010101010101010101010");
			var state = new SpongeState(bitString, 32);
			Assert.AreEqual(50, state.Size.B);
			Assert.AreEqual(32, state.Rate);
			Assert.AreEqual(18, state.Capacity);

			for (var i = 0; i < 50; i++)
			{
				if ((i & 1) == 0)
				{
					Assert.IsTrue(state[i]);
				}
				else
				{
					Assert.IsFalse(state[i]);
				}
			}
		}

		[TestMethod, TestCategory(Category), ExpectedException(typeof(ArgumentException))]
		public void Constructor_BitstringRate_ShouldThrow_WhenEmptyBitstring()
		{
			var bitString = new BitString();
			var state = new SpongeState(bitString, 1);
		}

		[TestMethod, TestCategory(Category), ExpectedException(typeof(ArgumentException))]
		public void Constructor_BitstringRate_ShouldThrow_WhenRateLowerThanOne()
		{
			var bitString = new BitString("10101010101010101010101010101010101010101010101010");
			var state = new SpongeState(bitString, 0);
		}

		[TestMethod, TestCategory(Category), ExpectedException(typeof(ArgumentException))]
		public void Constructor_BitstringRate_ShouldThrow_WhenRateGreaterThanOrEqualToB()
		{
			var bitString = new BitString("10101010101010101010101010101010101010101010101010");
			var state = new SpongeState(bitString, 50);
		}

		[TestMethod, TestCategory(Category)]
		public void Constructor_SpongeSizeRate_ShouldCreateExpectedState()
		{
			var state = new SpongeState(SpongeSize.W04, 72);
			Assert.AreEqual(100, state.Size.B);
			Assert.AreEqual(72, state.Rate);
			Assert.AreEqual(28, state.Capacity);
		}

		[TestMethod, TestCategory(Category), ExpectedException(typeof(ArgumentException))]
		public void Constructor_SpongeSizeRate_ShouldThrow_WhenRateLowerThanOne()
		{
			var state = new SpongeState(SpongeSize.W04, 0);
		}

		[TestMethod, TestCategory(Category), ExpectedException(typeof(ArgumentException))]
		public void Constructor_SpongeSizeRate_ShouldThrow_WhenRateGreaterThanOrEqualToB()
		{
			var state = new SpongeState(SpongeSize.W04, 100);
		}

		[TestMethod, TestCategory(Category)]
		public void Constructor_SpongeState_ShouldCopy()
		{
			var state = new SpongeState(BitString.Random(new Random(), 100), 72);
			var copy = new SpongeState(state);
			Assert.AreNotSame(state, copy);
			Assert.AreNotSame(state.BitString, copy.BitString);
			Assert.AreEqual(state.BitString, copy.BitString);
		}

		[TestMethod, TestCategory(Category)]
		public void Clear_ShouldClearState()
		{
			var state = new SpongeState(BitString.Random(new Random(), 48), 24);
			Assert.IsTrue(state.BitString.Any(b => b));
			state.Clear();
			Assert.IsFalse(state.BitString.Any(b => b));
		}

		[TestMethod, TestCategory(Category)]
		public void GetBits_ShouldEnumerateBitstring()
		{
			var state = new SpongeState(new BitString("01010101010101010101010101010101010101010101010101"), 25);
			var i = 0;

			foreach (var bit in state.GetBits())
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
		public void GetIndex_Coordinates_ShouldReturnCorrectIndex()
		{
			var state = new SpongeState(new BitString("1001001011101011110011010"), 12);
			for (var x = 0; x < 5; x++)
			{
				for (var y = 0; y < 5; y++)
				{
					for (var z = 0; z < 1; z++)
					{
						Assert.AreEqual((5 * y) + x + z, state.GetIndex(x, y, z));
					}
				}
			}
		}

		[TestMethod, TestCategory(Category)]
		public void GetBit_ShouldReturnExpectedBit()
		{
			var state = new SpongeState(new BitString("1010101010101010101010101"), 13);
			for (var i = 0; i < 25; i++)
			{
				if ((i & 1) == 0)
				{
					Assert.IsTrue(state.GetBit(i).Value);
				}
				else
				{
					Assert.IsFalse(state.GetBit(i).Value);
				}
			}
		}

		[TestMethod, TestCategory(Category)]
		public void GetColumn_ShouldReturnExpectedColumn()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			for (var x = 0; x < 5; x++)
			{
				for (var z = 0; z < 2; z++)
				{
					var column = state.GetColumn(x, z);
					foreach (var bit in column.GetBits())
					{
						if ((z & 1) == 0)
						{
							Assert.IsTrue(bit);
						}
						else

						{
							Assert.IsFalse(bit);
						}
					}
				}
			}
		}

		[TestMethod, TestCategory(Category)]
		public void GetColumns_ShouldEnumerateColumns()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			foreach (var column in state.GetColumns())
			{
				foreach (var bit in column.GetBits())
				{
					if ((column.Z & 1) == 0)
					{
						Assert.IsTrue(bit);
					}
					else
					{
						Assert.IsFalse(bit);
					}
				}
			}
		}

		[TestMethod, TestCategory(Category)]
		public void GetLane_ShouldReturnExpectedLane()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			for (var y = 0; y < 5; y++)
			{
				for (var x = 0; x < 5; x++)
				{
					var lane = state.GetLane(x, y);
					var bits = lane.GetBits().ToArray();
					Assert.AreEqual(2, bits.Length);
					Assert.IsTrue(bits[0]);
					Assert.IsFalse(bits[1]);
				}
			}
		}

		[TestMethod, TestCategory(Category)]
		public void GetLanes_ShouldEnumerateLanes()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			foreach (var lane in state.GetLanes())
			{
				var bits = lane.GetBits().ToArray();
				Assert.AreEqual(2, bits.Length);
				Assert.IsTrue(bits[0]);
				Assert.IsFalse(bits[1]);
			}
		}

		[TestMethod, TestCategory(Category)]
		public void GetPlane_ShouldReturnExpectedPlane()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			for (var y = 0; y < 5; y++)
			{
				var plane = state.GetPlane(y);
				var z = 0;

				foreach (var row in plane.GetRows())
				{
				    var rowCheck = (z & 1) == 0
				        ? row.GetBits().All(b => b)
				        : row.GetBits().All(b => !b);

                    Assert.IsTrue(rowCheck);
				    z++;
				}
			}
		}

		[TestMethod, TestCategory(Category)]
		public void GetPlanes_ShouldEnumeratePlanes()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			foreach (var plane in state.GetPlanes())
			{
				var z = 0;
				foreach (var row in plane.GetRows())
				{
				    var rowCheck = (z & 1) == 0
				        ? row.GetBits().All(b => b)
				        : row.GetBits().All(b => !b);

                    Assert.IsTrue(rowCheck);
				    z++;
				}
			}
		}

		[TestMethod, TestCategory(Category)]
		public void GetRow_ShouldReturnExpectedRow()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			for (var y = 0; y < 5; y++)
			{
				for (var z = 0; z < 2; z++)
				{
				    var row = state.GetRow(y, z);
				    var rowCheck = (z & 1) == 0
				        ? row.GetBits().All(b => b)
				        : row.GetBits().All(b => !b);

                    Assert.IsTrue(rowCheck);
				}
			}
		}

		[TestMethod, TestCategory(Category)]
		public void GetRows_ShouldEnumerateRows()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			foreach (var row in state.GetRows())
			{
			    var rowCheck = (row.Z & 1) == 0
			        ? row.GetBits().All((b) => b)
			        : row.GetBits().All((b) => !b);

                Assert.IsTrue(rowCheck);
			}
		}

		[TestMethod, TestCategory(Category)]
		public void GetSheet_ShouldReturnExpectedSheet()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			for (var x = 0; x < 5; x++)
			{
				var sheet = state.GetSheet(x);
				foreach (var column in sheet.GetColumns())
				{
				    var colCheck = (column.Z & 1) == 0
				        ? column.GetBits().All((b) => b)
				        : column.GetBits().All((b) => !b);

                    Assert.IsTrue(colCheck);
				}
			}
		}

		[TestMethod, TestCategory(Category)]
		public void GetSheets_ShouldEnumerateSheets()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			foreach (var sheet in state.GetSheets())
			{
				foreach (var column in sheet.GetColumns())
				{
				    var colCheck = (column.Z & 1) == 0
				        ? column.GetBits().All((b) => b)
				        : column.GetBits().All((b) => !b);

                    Assert.IsTrue(colCheck);
				}
			}
		}

		[TestMethod, TestCategory(Category)]
		public void GetSlice_ShouldReturnExpectedSlice()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			for (var z = 0; z < 2; z++)
			{
				var slice = state.GetSlice(z);
				foreach (var column in slice.GetColumns())
				{
				    var colCheck = (column.Z & 1) == 0
				        ? column.GetBits().All((b) => b)
				        : column.GetBits().All((b) => !b);

                    Assert.IsTrue(colCheck);
				}
			}
		}

		[TestMethod, TestCategory(Category)]
		public void GetSlices_ShouldEnumerateSlices()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			foreach (var slice in state.GetSlices())
			{
				foreach (var column in slice.GetColumns())
				{
				    var colCheck = (column.Z & 1) == 0
				        ? column.GetBits().All((b) => b)
				        : column.GetBits().All((b) => !b);

                    Assert.IsTrue(colCheck);
				}
			}
		}

		[TestMethod, TestCategory(Category)]
		public void SetColumn_ShouldSetColumnBits()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			var column = state.GetColumn(0, 0);
			state.SetColumn(column, new[] { false, false, false, false, false });

			for (var y = 0; y < 5; y++)
			{
				Assert.IsTrue(column.GetBits().All((b) => !b));
			}
		}

		[TestMethod, TestCategory(Category)]
		public void SetColumns_ShouldSetColumns()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			var bits = new bool[50];
			state.SetColumns(bits);
			Assert.AreEqual("00000000000000000000000000000000000000000000000000", state.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void SetLane_ShouldSetLaneBits()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			var lane = state.GetLane(0, 0);
			state.SetLane(lane, new[] { false, true });
			Assert.AreEqual("01101010101010101010101010101010101010101010101010", state.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void SetLanes_ShouldSetLanes()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			var bits = new bool[50];
			state.SetLanes(bits);
			Assert.AreEqual("00000000000000000000000000000000000000000000000000", state.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void SetPlane_ShouldSetPlaneBits()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			var plane = state.GetPlane(0);
			state.SetPlane(plane, new[] { false, true, false, true, false, true, false, true, false, true });
			Assert.AreEqual("01010101011010101010101010101010101010101010101010", state.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void SetPlanes_ShouldSetPlanes()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			var bits = new bool[50];
			state.SetPlanes(bits);
			Assert.AreEqual("00000000000000000000000000000000000000000000000000", state.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void SetRow_ShouldSetRowBits()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			var row = state.GetRow(0, 0);
			state.SetRow(row, new bool[5]);
			Assert.AreEqual("00000000001010101010101010101010101010101010101010", state.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void SetRows_ShouldSetRows()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			var bits = new bool[50];
			state.SetRows(bits);
			Assert.AreEqual("00000000000000000000000000000000000000000000000000", state.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void SetSheet_ShouldSetSheetBits()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			var sheet = state.GetSheet(0);
			state.SetSheet(sheet, new[] { false, true, false, true, false, true, false, true, false, true });
			Assert.AreEqual("01101010100110101010011010101001101010100110101010", state.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void SetSheets_ShouldSetSheets()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			var bits = new bool[50];
			state.SetSheets(bits);
			Assert.AreEqual("00000000000000000000000000000000000000000000000000", state.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void SetSlice_ShouldSetSliceBits()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			var slice = state.GetSlice(0);
			state.SetSlice(slice, new bool[25]);
			Assert.AreEqual("00000000000000000000000000000000000000000000000000", state.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void SetSlices_ShouldSetSlices()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			var bits = new bool[50];
			state.SetSlices(bits);
			Assert.AreEqual("00000000000000000000000000000000000000000000000000", state.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void Xor_ShouldXorWithByteArray()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			var bytes = new byte[] { 255, 255, 255, 255, 255, 255, 255 };
			state.Xor(bytes);
			Assert.AreEqual("01010101010101010101010101010101010101010101010101", state.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void XorColumn_ShouldPerformBitwiseXorWithBits()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			var column = state.GetColumn(0, 0);
			var bits = new[] { true, true, true, true, true };
			state.XorColumn(column, bits);
			Assert.AreEqual("00101010100010101010001010101000101010100010101010", state.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void XorColumns_ShouldPerformBitwiseXorForColumns()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			var bits = new bool[50];

			for (var i = 0; i < 50; i++)
			{
				bits[i] = true;
			}

			state.XorColumns(bits);
			Assert.AreEqual("01010101010101010101010101010101010101010101010101", state.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void XorLane_ShouldPerformBitwiseXorWithBits()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			var lane = state.GetLane(0, 0);
			var bits = new[] { true, true };
			state.XorLane(lane, bits);
			Assert.AreEqual("01101010101010101010101010101010101010101010101010", state.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void XorLanes_ShouldPerformBitwiseXorForLanes()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			var bits = new bool[50];

			for (var i = 0; i < 50; i++)
			{
				bits[i] = true;
			}

			state.XorLanes(bits);
			Assert.AreEqual("01010101010101010101010101010101010101010101010101", state.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void XorPlane_ShouldPerformBitwiseXorWithBits()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			var plane = state.GetPlane(0);
			var bits = new[] { true, true, true, true, true, true, true, true, true, true };
			state.XorPlane(plane, bits);
			Assert.AreEqual("01010101011010101010101010101010101010101010101010", state.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void XorPlanes_ShouldPerformBitwiseXorForPlanes()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			var bits = new bool[50];

			for (var i = 0; i < 50; i++)
			{
				bits[i] = true;
			}

			state.XorPlanes(bits);
			Assert.AreEqual("01010101010101010101010101010101010101010101010101", state.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void XorRow_ShouldPerformBitwiseXorWithBits()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			var row = state.GetRow(0, 0);
			var bits = new[] { true, true, true, true, true };
			state.XorRow(row, bits);
			Assert.AreEqual("00000000001010101010101010101010101010101010101010", state.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void XorRows_ShouldPerformBitwiseXorForRows()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			var bits = new bool[50];

			for (var i = 0; i < 50; i++)
			{
				bits[i] = true;
			}

			state.XorRows(bits);
			Assert.AreEqual("01010101010101010101010101010101010101010101010101", state.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void XorSheet_ShouldPerformBitwiseXorWithBits()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			var sheet = state.GetSheet(0);
			var bits = new[] { true, true, true, true, true, true, true, true, true, true };
			state.XorSheet(sheet, bits);
			Assert.AreEqual("01101010100110101010011010101001101010100110101010", state.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void XorSheets_ShouldPerformBitwiseXorForSheets()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			var bits = new bool[50];

			for (var i = 0; i < 50; i++)
			{
				bits[i] = true;
			}

			state.XorSheets(bits);
			Assert.AreEqual("01010101010101010101010101010101010101010101010101", state.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void XorSlice_ShouldPerformBitwiseXorWithBits()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			var slice = state.GetSlice(0);
			var bits = new bool[25];

			for (var i = 0; i < 25; i++)
			{
				bits[i] = true;
			}

			state.XorSlice(slice, bits);
			Assert.AreEqual("00000000000000000000000000000000000000000000000000", state.ToBinString());
		}

		[TestMethod, TestCategory(Category)]
		public void XorSlices_ShouldPerformBitwiseXorForSlices()
		{
			var state = new SpongeState(new BitString("10101010101010101010101010101010101010101010101010"), 25);
			var bits = new bool[50];

			for (var i = 0; i < 50; i++)
			{
				bits[i] = true;
			}

			state.XorSlices(bits);
			Assert.AreEqual("01010101010101010101010101010101010101010101010101", state.ToBinString());
		}
	}
}
