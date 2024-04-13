using Ionic.Zlib;
using System.IO.Hashing;

using System.Runtime.InteropServices;
using System.Text;

namespace DecryptCocos2dAsset {
    class Program {
        // original
        // https://github.com/cocos2d/cocos2d-x/blob/v3/cocos/base/ZipUtils.h
        // https://github.com/cocos2d/cocos2d-x/blob/v3/cocos/base/ZipUtils.cpp
        static uint[] s_uEncryptedPvrKeyParts = new uint[4];
        static uint[] s_uEncryptionKey = new uint[1024];

        static void SetKey(uint key1, uint key2, uint key3, uint key4) {
            s_uEncryptedPvrKeyParts[0] = key1;
            s_uEncryptedPvrKeyParts[1] = key2;
            s_uEncryptedPvrKeyParts[2] = key3;
            s_uEncryptedPvrKeyParts[3] = key4;
        }

        static uint MX(uint z, uint y, uint p, uint e, uint sum) =>
            (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (s_uEncryptedPvrKeyParts[(p & 3) ^ e] ^ z)));

        static void InitializeKey() {
            const int enclen = 1024;

            uint y, p, e;
            uint rounds = 6;
            uint sum = 0;
            uint z = s_uEncryptionKey[enclen - 1];

            do {
                uint DELTA = 0x9e3779b9;

                sum += DELTA;
                e = (sum >> 2) & 3;

                for (p = 0; p < enclen - 1; p++) {
                    y = s_uEncryptionKey[p + 1];
                    z = s_uEncryptionKey[p] += MX(z, y, p, e, sum);
                }

                y = s_uEncryptionKey[0];
                z = s_uEncryptionKey[enclen - 1] += MX(z, y, p, e, sum);

            } while (--rounds > 0);
        }

        static void Decrypt(ref byte[] bytes, int len) {
            const int enclen = 1024;
            const int securelen = 512 * 4;
            const int distance = 64 * 4;

            var b = 0;
            var i = 0;

            for (; i < len && i < securelen; i += 4) {
                var key = BitConverter.GetBytes(s_uEncryptionKey[b++]);
                bytes[i + 0] ^= key[0];
                bytes[i + 1] ^= key[1];
                bytes[i + 2] ^= key[2];
                bytes[i + 3] ^= key[3];

                if (b >= enclen) {
                    b = 0;
                }
            }

            for (; i < len; i += distance) {
                var key = BitConverter.GetBytes(s_uEncryptionKey[b++]);
                bytes[i + 0] ^= key[0];
                bytes[i + 1] ^= key[1];
                bytes[i + 2] ^= key[2];
                bytes[i + 3] ^= key[3];

                if (b >= enclen) {
                    b = 0;
                }
            }
        }

        struct DDSHeader {
            public byte sig1;
            public byte sig2;
            public byte sig3;
            public bool compressed;
            public int reserved;
        };

        static bool DoFile(string path, string outPath) {

            var bytes = File.ReadAllBytes(path);
            MemoryMarshal.TryRead<DDSHeader>(bytes, out var header);

            if (header.sig1 != 'D' || header.sig2 != 'D' || header.sig3 != 'S')
                return false;

            bytes = bytes.Skip(8).ToArray();
            Decrypt(ref bytes, bytes.Length);

            var len = BitConverter.ToInt32(bytes, 0);
            bytes = bytes.Skip(4).Take(len).ToArray();

            if (header.compressed)
                bytes = ZlibStream.UncompressBuffer(bytes);

            if (bytes.Length > 4 && (bytes[0] == 'C' && bytes[1] == 'C' && bytes[2] == 'Z')) {
                if (bytes[3] == 'p') {
                    throw new NotSupportedException("CCZ protected files are not supported");
                }
                else if (bytes[3] != '!') {
                    throw new NotSupportedException("what tf?");
                }
                bytes = bytes.Skip(16).ToArray();
                bytes = ZlibStream.UncompressBuffer(bytes);
            }
            Directory.CreateDirectory(Path.GetDirectoryName(outPath));

            if (Path.GetExtension(outPath) == ".png")
                outPath = Path.ChangeExtension(outPath, ".pvr.ccz");
            File.WriteAllBytes(outPath, bytes);
            return true;
        }

        static void Main(string[] args) {
            var p1 = XxHash32.HashToUInt32(Encoding.ASCII.GetBytes("ERROR_TMP_1001"));
            var p2 = XxHash32.HashToUInt32(Encoding.ASCII.GetBytes("ERROR_TMP_9931"));
            var p3 = XxHash32.HashToUInt32(Encoding.ASCII.GetBytes("ERROR_TMP_0023"));
            var p4 = XxHash32.HashToUInt32(Encoding.ASCII.GetBytes("ERROR_TMP_5238"));
            SetKey(p1, p2, p3, p4);
            InitializeKey();

            var inputPath = args[0];
            var outputPath = args[1];

            foreach (var file in Directory.EnumerateFiles(inputPath, "*.*", SearchOption.AllDirectories)) {
                var aa = Path.GetRelativePath(inputPath, file);
                Console.WriteLine($"Trying: {aa}");
                if (DoFile(file, Path.Combine(outputPath, aa))) {
                    Console.WriteLine($"Decrypted {aa}");
                }
            }
        }
    }
}