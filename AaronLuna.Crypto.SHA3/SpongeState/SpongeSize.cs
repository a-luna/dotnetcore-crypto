namespace AaronLuna.Crypto.SHA3
{
    public struct SpongeSize
    {
        // B=25, W=1, L=0
        public static readonly SpongeSize W01 = new SpongeSize(25);
        // B=50, W=2, L=1
        public static readonly SpongeSize W02 = new SpongeSize(50);
        // B=100, W=4, L=2
        public static readonly SpongeSize W04 = new SpongeSize(100);
        // B=200, W=8, L=3
        public static readonly SpongeSize W08 = new SpongeSize(200);
        // B=400, W=16, L=4
        public static readonly SpongeSize W16 = new SpongeSize(400);
        // B=800, W=32, L=5
        public static readonly SpongeSize W32 = new SpongeSize(800);
        // B=1600, W=64, L=6
        public static readonly SpongeSize W64 = new SpongeSize(1600);

        // The total number of bits in the sponge state
        public int B { get; }

        // The base-2 logarithm of W
        public int L => BinaryFunctions.Log2(W);

        // The depth of the sponge state.
        public int W => B / 25;

        internal SpongeSize(int b)
        {
            B = b;
        }

        public override string ToString()
        {
            return $"B={B}, W={W}, L={L}";
        }
    }
}