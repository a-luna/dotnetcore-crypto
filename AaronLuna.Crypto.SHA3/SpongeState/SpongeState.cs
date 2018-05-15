namespace AaronLuna.Crypto.SHA3
{
    using System;
    using System.Collections.Generic;

    public sealed class SpongeState
	{
		delegate bool OperationDelegate(int x, int y, int z, bool bit);

        BitString _bitString;

		public BitString BitString
        {
            get => _bitString;

            set
            {
                if (value == null || value.Length != Size.B)
                {
                    throw new ArgumentException($"Invalid bitString length {value} instead of {Size.B}", nameof(value));
                }

                _bitString = value;
            }
        }

        public int Capacity => Size.B - Rate;
        public int Rate { get; }
        public SpongeSize Size { get; }

        public bool this[int index]
        {
			get => _bitString[index];
            set => _bitString[index] = value;
        }

		public bool this[int x, int y, int z]
		{
            get => this[GetIndex(x, y, z)];
            set => this[GetIndex(x, y, z)] = value;
        }

		public SpongeState(SpongeState state)
		{
			Size = state.Size;
			Rate = state.Rate;
			_bitString = new BitString(state._bitString);
		}

		public SpongeState(SpongeSize size, int rate)
		{
			var b = size.B;
			if (rate < 1 || rate >= b)
			{
				throw new ArgumentException($"Invalid rate {rate} for width {b}.", nameof(rate));
			}

			Size = size;
			Rate = rate;
			_bitString = BitString.Zeroes(b);
		}

		public SpongeState(BitString bitString, int rate)
		{
			_bitString = bitString ?? throw new ArgumentNullException(nameof(bitString));

			var length = _bitString.Length;
			if (length < 1)
			{
				throw new ArgumentException("BitString cannot be empty.", nameof(bitString));
			}

			Size = new SpongeSize(length);
			if (rate < 1 || rate >= Size.B)
			{
				throw new ArgumentException($"Invalid rate {rate} for width {Size.B}.", nameof(rate));
			}

			Rate = rate;
		}

	    public void Clear()
	    {
			_bitString.Clear();
		}

		public IEnumerable<bool> GetBits()
		{
			return _bitString;
		}

		public int GetIndex(SpongeBit spongeBit)
		{
			return GetIndex(spongeBit.X, spongeBit.Y, spongeBit.Z);
		}

	    public int GetIndex(int x, int y, int z)
	    {
			return Size.W * (5 * y + x) + z;
		}

		public string ToBinString(int spacing = 0)
		{
			return _bitString.ToBinString(spacing);
		}

		public string ToHexString(bool spacing = true, bool uppercase = true)
		{
			return _bitString.ToHexString(spacing, uppercase);
		}

		public override string ToString()
		{
			return $"State ({Size}): {_bitString.ToHexString()}";
		}

	    public SpongeBit GetBit(int index)
	    {
			// index = _size.W * (5 * y + x) + z
			var w = Size.W;
			var wCount = index / w;

			// wCount = 5 * y + x
			var y = wCount / 5;
			var x = wCount - 5 * y;
			var z = BinaryFunctions.Mod(index, w);

			return new SpongeBit(this, x, y, z);
		}

		public Column GetColumn(int x, int z)
		{
			return new Column(this, x, z);
		}

		public IEnumerable<Column> GetColumns()
		{
			var w = Size.W;
			for (var x = 0; x < 5; x++)
			{
				for (var z = 0; z < w; z++)
				{
					yield return new Column(this, x, z);
				}
			}
		}

		public Lane GetLane(int x, int y)
		{
			return new Lane(this, x, y);
		}

		public IEnumerable<Lane> GetLanes()
		{
			for (var y = 0; y < 5; y++)
			{
				for (var x = 0; x < 5; x++)
				{
					yield return new Lane(this, x, y);
				}
			}
		}

		public Plane GetPlane(int y)
		{
			return new Plane(this, y);
		}

		public IEnumerable<Plane> GetPlanes()
		{
			for (var y = 0; y < 5; y++)
			{
				yield return new Plane(this, y);
			}
		}

		public Row GetRow(int y, int z)
		{
			return new Row(this, y, z);
		}

		public IEnumerable<Row> GetRows()
		{
			var w = Size.W;
			for (var y = 0; y < 5; y++)
			{
				for (var z = 0; z < w; z++)
				{
					yield return new Row(this, y, z);
				}
			}
		}

		public Sheet GetSheet(int x)
		{
			return new Sheet(this, x);
		}

		public IEnumerable<Sheet> GetSheets()
		{
			for (var x = 0; x < 5; x++)
			{
				yield return new Sheet(this, x);
			}
		}

		public Slice GetSlice(int z)
		{
			return new Slice(this, z);
		}

		public IEnumerable<Slice> GetSlices()
		{
			var w = Size.W;
			for (var z = 0; z < w; z++)
			{
				yield return new Slice(this, z);
			}
		}

        public void SetColumn(Column column, IEnumerable<bool> bits) =>
            ColumnOperation((x, y, z, bit) => bit, column, bits);

        public void SetColumns(IEnumerable<bool> bits) =>
            ColumnsOperation((x, y, z, bit) => bit, bits);

        public void SetLane(Lane lane, IEnumerable<bool> bits) =>
            LaneOperation((x, y, z, bit) => bit, lane, bits);

        public void SetLanes(IEnumerable<bool> bits) =>
            LanesOperation((x, y, z, bit) => bit, bits);

        public void SetPlane(Plane plane, IEnumerable<bool> bits) =>
            PlaneOperation((x, y, z, bit) => bit, plane, bits);

        public void SetPlanes(IEnumerable<bool> bits) =>
            PlanesOperation((x, y, z, bit) => bit, bits);

        public void SetRow(Row row, IEnumerable<bool> bits) =>
            RowOperation((x, y, z, bit) => bit, row, bits);

        public void SetRows(IEnumerable<bool> bits) =>
            RowsOperation((x, y, z, bit) => bit, bits);

        public void SetSheet(Sheet sheet, IEnumerable<bool> bits) =>
            SheetOperation((x, y, z, bit) => bit, sheet, bits);

        public void SetSheets(IEnumerable<bool> bits) =>
            SheetsOperation((x, y, z, bit) => bit, bits);

        public void SetSlice(Slice slice, IEnumerable<bool> bits) =>
            SliceOperation((x, y, z, bit) => bit, slice, bits);

        public void SetSlices(IEnumerable<bool> bits) =>
            SlicesOperation((x, y, z, bit) => bit, bits);

        public void Xor(byte[] data)
        {
			_bitString.Xor(data);
		}

        public void XorColumn(Column column, IEnumerable<bool> bits) =>
            ColumnOperation((x, y, z, bit) => this[x, y, z] ^ bit, column, bits);

        public void XorColumns(IEnumerable<bool> bits) =>
            ColumnsOperation((x, y, z, bit) => this[x, y, z] ^ bit, bits);

        public void XorLane(Lane lane, IEnumerable<bool> bits) =>
            LaneOperation((x, y, z, bit) => this[x, y, z] ^ bit, lane, bits);

        public void XorLanes(IEnumerable<bool> bits) =>
            LanesOperation((x, y, z, bit) => this[x, y, z] ^ bit, bits);

        public void XorPlane(Plane plane, IEnumerable<bool> bits) =>
            PlaneOperation((x, y, z, bit) => this[x, y, z] ^ bit, plane, bits);

        public void XorPlanes(IEnumerable<bool> bits) =>
            PlanesOperation((x, y, z, bit) => this[x, y, z] ^ bit, bits);

        public void XorRow(Row row, IEnumerable<bool> bits) =>
            RowOperation((x, y, z, bit) => this[x, y, z] ^ bit, row, bits);

        public void XorRows(IEnumerable<bool> bits) =>
            RowsOperation((x, y, z, bit) => this[x, y, z] ^ bit, bits);

        public void XorSheet(Sheet sheet, IEnumerable<bool> bits) =>
            SheetOperation((x, y, z, bit) => this[x, y, z] ^ bit, sheet, bits);

        public void XorSheets(IEnumerable<bool> bits) =>
            SheetsOperation((x, y, z, bit) => this[x, y, z] ^ bit, bits);

        public void XorSlice(Slice slice, IEnumerable<bool> bits) =>
            SliceOperation((x, y, z, bit) => this[x, y, z] ^ bit, slice, bits);

        public void XorSlices(IEnumerable<bool> bits) =>
            SlicesOperation((x, y, z, bit) => this[x, y, z] ^ bit, bits);

        void ColumnOperation(OperationDelegate function, Column column, IEnumerable<bool> bits)
        {
			var y = 0;
			foreach (var bit in bits)
			{
				this[GetIndex(column.X, y, column.Z)] = function(column.X, y, column.Z, bit);
				y++;
			}
		}

		void ColumnsOperation(OperationDelegate function, IEnumerable<bool> bits)
		{
			var w = Size.W;
			var x = 0;
			var y = 0;
			var z = 0;

			foreach (var bit in bits)
			{
				this[GetIndex(x, y, z)] = function(x, y, z, bit);

				if (++y == 5)
				{
					y = 0;
					z++;
				}

			    if (z != w) continue;
			    z = 0;
			    x++;
			}
		}

		void LaneOperation(OperationDelegate function, Lane lane, IEnumerable<bool> bits)
		{
			var z = 0;
			foreach (var bit in bits)
			{
				this[GetIndex(lane.X, lane.Y, z)] = function(lane.X, lane.Y, z, bit);
				z++;
			}
		}

		void LanesOperation(OperationDelegate function, IEnumerable<bool> bits)
		{
			var w = Size.W;
			var x = 0;
			var y = 0;
			var z = 0;

			foreach (var bit in bits)
			{
				this[GetIndex(x, y, z)] = function(x, y, z, bit);

				if (++z == w)
				{
					z = 0;
					x++;
				}

			    if (x != 5) continue;
			    x = 0;
			    y++;
			}
		}

		void PlaneOperation(OperationDelegate function, Plane plane, IEnumerable<bool> bits)
		{
			var w = Size.W;
			var x = 0;
			var z = 0;

			foreach (var bit in bits)
			{
				this[GetIndex(x, plane.Y, z)] = function(x, plane.Y, z, bit);

			    if (++z != w) continue;
			    z = 0;
			    x++;
			}
		}

		void PlanesOperation(OperationDelegate function, IEnumerable<bool> bits)
		{
			var w = Size.W;
			var x = 0;
			var y = 0;
			var z = 0;

			foreach (var bit in bits)
			{
				this[GetIndex(x, y, z)] = function(x, y, z, bit);

				if (++z == w)
				{
					z = 0;
					x++;
				}

			    if (x != 5) continue;
			    x = 0;
			    y++;
			}
		}

		void RowOperation(OperationDelegate function, Row row, IEnumerable<bool> bits)
		{
			var x = 0;
			foreach (var bit in bits)
			{
				this[GetIndex(x, row.Y, row.Z)] = function(x, row.Y, row.Z, bit);
				x++;
			}
		}

		void RowsOperation(OperationDelegate function, IEnumerable<bool> bits)
		{
			var w = Size.W;
			var x = 0;
			var y = 0;
			var z = 0;

			foreach (var bit in bits)
			{
				this[GetIndex(x, y, z)] = function(x, y, z, bit);

				if (++x == 5)
				{
					x = 0;
					z++;
				}

			    if (z != w) continue;
			    z = 0;
			    y++;
			}
		}

		void SheetOperation(OperationDelegate function, Sheet sheet, IEnumerable<bool> bits)
		{
			var w = Size.W;
			var y = 0;
			var z = 0;

			foreach (var bit in bits)
			{
				this[GetIndex(sheet.X, y, z)] = function(sheet.X, y, z, bit);

			    if (++z != w) continue;
			    z = 0;
			    y++;
			}
		}

		void SheetsOperation(OperationDelegate function, IEnumerable<bool> bits)
		{
			var w = Size.W;
			var x = 0;
			var y = 0;
			var z = 0;

			foreach (var bit in bits)
			{
				this[GetIndex(x, y, z)] = function(x, y, z, bit);

				if (++z == w)
				{
					z = 0;
					y++;
				}

			    if (y != 5) continue;
			    y = 0;
			    x++;
			}
		}

		void SliceOperation(OperationDelegate function, Slice slice, IEnumerable<bool> bits)
		{
			var x = 0;
			var y = 0;

			foreach (var bit in bits)
			{
				this[GetIndex(x, y, slice.Z)] = function(x, y, slice.Z, bit);

			    if (++x != 5) continue;
			    x = 0;
			    y++;
			}
		}

		void SlicesOperation(OperationDelegate function, IEnumerable<bool> bits)
		{
		    var x = 0;
			var y = 0;
			var z = 0;

			foreach (var bit in bits)
			{
				this[GetIndex(x, y, z)] = function(x, y, z, bit);

				if (++x == 5)
				{
					x = 0;
					y++;
				}

			    if (y != 5) continue;
			    y = 0;
			    z++;
			}
		}

		internal void SetBitString(BitString bitString)
		{
			_bitString = bitString;
		}
	}
}
