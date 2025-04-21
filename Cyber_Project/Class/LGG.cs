namespace Cyber_Project.Class
{
    public class LGG
    {
        private long _seed;
        private const long a = 1664525;
        private const long c = 1013904223;
        private const long m = 4294967296; // 2^32

        public LGG(long seed)
        {
            _seed = seed;
        }

        public long Generate()
        {
            _seed = (a * _seed + c) % m;
            return _seed;
        }
    }
}
