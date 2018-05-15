namespace AaronLuna.Crypto.SHA3.Test
{
    using SHA3;

    using Microsoft.VisualStudio.TestTools.UnitTesting;

    [TestClass]
	public class BinaryFunctionsTest
	{
		const string Category = "BinaryFunctions";

		[TestMethod, TestCategory(Category)]
		public void Log2_ShouldReturnExpectedValues()
		{
			for (var i = 0; i < 32; i++)
			{
				Assert.AreEqual(i, BinaryFunctions.Log2(1 << i));
			}
		}

		[TestMethod, TestCategory(Category)]
		public void LowerMask_ShouldReturnExpectedValues()
		{
			Assert.AreEqual((byte)0, BinaryFunctions.LowerMask(0));
			Assert.AreEqual((byte)1, BinaryFunctions.LowerMask(1));
			Assert.AreEqual((byte)3, BinaryFunctions.LowerMask(2));
			Assert.AreEqual((byte)7, BinaryFunctions.LowerMask(3));
			Assert.AreEqual((byte)15, BinaryFunctions.LowerMask(4));
			Assert.AreEqual((byte)31, BinaryFunctions.LowerMask(5));
			Assert.AreEqual((byte)63, BinaryFunctions.LowerMask(6));
			Assert.AreEqual((byte)127, BinaryFunctions.LowerMask(7));
			Assert.AreEqual((byte)255, BinaryFunctions.LowerMask(8));
		}

		[TestMethod, TestCategory(Category)]
		public void Mod_ShouldReturnExpectedValues()
		{
			Assert.AreEqual(5, BinaryFunctions.Mod(13, 8));
			Assert.AreEqual(4, BinaryFunctions.Mod(-1, 5));
		}
	}
}
