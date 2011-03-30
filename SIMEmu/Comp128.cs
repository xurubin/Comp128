using System;
using System.Collections.Generic;
//using System.Linq;
using System.Text;

namespace SIMEmu
{
    class IntComparer<T> : IComparer<T>
    {
        public delegate int IntTransformer(T x);
        IntTransformer t;
        public IntComparer(IntTransformer t) { this.t = t; }

        public int Compare(T x, T y)
        {
            return t(x).CompareTo(t(y));
        }
    }
    class HammingDistance
    {
        public static int int_hamming(int x)
        {
            int r = 0;
            for (int i = 0; i < 32; i++)
            {
                r = r + (x & 1);
                x >>= 1;
            }
            return r;
        }
        public static int long_hamming(long x)
        {
            return int_hamming((int)x) + int_hamming((int)(x >> 32));
        }
    }
    class Comp128
    {
        /* 
        * rand[0..15]: the challenge from the base station 
        * key[0..15]: the SIM's A3/A8 long-term key Ki 
        * simoutput[0..11]: what you'd get back if you fed rand and key to a real 
        * SIM. 
        * 
        *   The GSM spec states that simoutput[0..3] is SRES, 
        *   and simoutput[4..11] is Kc (the A5 session key). 
        *   (See GSM 11.11, Section 8.16.  See also the leaked document 
        *   referenced below.) 
        *   Note that Kc is bits 74..127 of the COMP128 output, followed by 10 
        *   zeros. 
        *   In other words, A5 is keyed with only 54 bits of entropy. This 
        *   represents a deliberate weakening of the key used for voice privacy 
        *   by a factor of over 1000. 
        * 
        * Verified with a Pacific Bell Schlumberger SIM.  Your mileage may vary. 
        * 
        * Marc Briceno <marc@scard.org>, Ian Goldberg <iang@cs.berkeley.edu>, 
        * and David Wagner <daw@cs.berkeley.edu> 
        */

        /* The compression tables. */
        static byte[] table_0 = { 
            102,177,186,162,  2,156,112, 75, 55, 25,  8, 12,251,193,246,188, 
            109,213,151, 53, 42, 79,191,115,233,242,164,223,209,148,108,161, 
            252, 37,244, 47, 64,211,  6,237,185,160,139,113, 76,138, 59, 70, 
            67, 26, 13,157, 63,179,221, 30,214, 36,166, 69,152,124,207,116, 
            247,194, 41, 84, 71,  1, 49, 14, 95, 35,169, 21, 96, 78,215,225, 
            182,243, 28, 92,201,118,  4, 74,248,128, 17, 11,146,132,245, 48, 
            149, 90,120, 39, 87,230,106,232,175, 19,126,190,202,141,137,176, 
            250, 27,101, 40,219,227, 58, 20, 51,178, 98,216,140, 22, 32,121, 
            61,103,203, 72, 29,110, 85,212,180,204,150,183, 15, 66,172,196, 
            56,197,158,  0,100, 45,153,  7,144,222,163,167, 60,135,210,231, 
            174,165, 38,249,224, 34,220,229,217,208,241, 68,206,189,125,255, 
            239, 54,168, 89,123,122, 73,145,117,234,143, 99,129,200,192, 82, 
            104,170,136,235, 93, 81,205,173,236, 94,105, 52, 46,228,198,  5, 
            57,254, 97,155,142,133,199,171,187, 50, 65,181,127,107,147,226, 
            184,218,131, 33, 77, 86, 31, 44, 88, 62,238, 18, 24, 43,154, 23, 
            80,159,134,111,  9,114,  3, 91, 16,130, 83, 10,195,240,253,119, 
            177,102,162,186,156,  2, 75,112, 25, 55, 12,  8,193,251,188,246, 
            213,109, 53,151, 79, 42,115,191,242,233,223,164,148,209,161,108, 
            37,252, 47,244,211, 64,237,  6,160,185,113,139,138, 76, 70, 59, 
            26, 67,157, 13,179, 63, 30,221, 36,214, 69,166,124,152,116,207, 
            194,247, 84, 41,  1, 71, 14, 49, 35, 95, 21,169, 78, 96,225,215, 
            243,182, 92, 28,118,201, 74,  4,128,248, 11, 17,132,146, 48,245, 
            90,149, 39,120,230, 87,232,106, 19,175,190,126,141,202,176,137, 
            27,250, 40,101,227,219, 20, 58,178, 51,216, 98, 22,140,121, 32, 
            103, 61, 72,203,110, 29,212, 85,204,180,183,150, 66, 15,196,172, 
            197, 56,  0,158, 45,100,  7,153,222,144,167,163,135, 60,231,210, 
            165,174,249, 38, 34,224,229,220,208,217, 68,241,189,206,255,125, 
            54,239, 89,168,122,123,145, 73,234,117, 99,143,200,129, 82,192, 
            170,104,235,136, 81, 93,173,205, 94,236, 52,105,228, 46,  5,198, 
            254, 57,155, 97,133,142,171,199, 50,187,181, 65,107,127,226,147, 
            218,184, 33,131, 86, 77, 44, 31, 62, 88, 18,238, 43, 24, 23,154, 
            159, 80,111,134,114,  9, 91,  3,130, 16, 10, 83,240,195,119,253 
            };
        static byte[] table_1 = { 
            19, 11, 80,114, 43,  1, 69, 94, 39, 18,127,117, 97,  3, 85, 43, 
            27,124, 70, 83, 47, 71, 63, 10, 47, 89, 79,  4, 14, 59, 11,  5, 
            35,107,103, 68, 21, 86, 36, 91, 85,126, 32, 50,109, 94,120,  6, 
            53, 79, 28, 45, 99, 95, 41, 34, 88, 68, 93, 55,110,125,105, 20, 
            90, 80, 76, 96, 23, 60, 89, 64,121, 56, 14, 74,101,  8, 19, 78, 
            76, 66,104, 46,111, 50, 32,  3, 39,  0, 58, 25, 92, 22, 18, 51, 
            57, 65,119,116, 22,109,  7, 86, 59, 93, 62,110, 78, 99, 77, 67, 
            12,113, 87, 98,102,  5, 88, 33, 38, 56, 23,  8, 75, 45, 13, 75, 
            95, 63, 28, 49,123,120, 20,112, 44, 30, 15, 98,106,  2,103, 29, 
            82,107, 42,124, 24, 30, 41, 16,108,100,117, 40, 73, 40,  7,114, 
            82,115, 36,112, 12,102,100, 84, 92, 48, 72, 97,  9, 54, 55, 74, 
            113,123, 17, 26, 53, 58,  4,  9, 69,122, 21,118, 42, 60, 27, 73, 
            118,125, 34, 15, 65,115, 84, 64, 62, 81, 70,  1, 24,111,121, 83, 
            104, 81, 49,127, 48,105, 31, 10,  6, 91, 87, 37, 16, 54,116,126, 
            31, 38, 13,  0, 72,106, 77, 61, 26, 67, 46, 29, 96, 37, 61, 52, 
            101, 17, 44,108, 71, 52, 66, 57, 33, 51, 25, 90,  2,119,122, 35 
            };
        static byte[] table_2 = { 
            52, 50, 44,  6, 21, 49, 41, 59, 39, 51, 25, 32, 51, 47, 52, 43, 
            37,  4, 40, 34, 61, 12, 28,  4, 58, 23,  8, 15, 12, 22,  9, 18, 
            55, 10, 33, 35, 50,  1, 43,  3, 57, 13, 62, 14,  7, 42, 44, 59, 
            62, 57, 27,  6,  8, 31, 26, 54, 41, 22, 45, 20, 39,  3, 16, 56, 
            48,  2, 21, 28, 36, 42, 60, 33, 34, 18,  0, 11, 24, 10, 17, 61, 
            29, 14, 45, 26, 55, 46, 11, 17, 54, 46,  9, 24, 30, 60, 32,  0, 
            20, 38,  2, 30, 58, 35,  1, 16, 56, 40, 23, 48, 13, 19, 19, 27, 
            31, 53, 47, 38, 63, 15, 49,  5, 37, 53, 25, 36, 63, 29,  5,  7 
            };
        static byte[] table_3 = { 
            1,  5, 29,  6, 25,  1, 18, 23, 17, 19,  0,  9, 24, 25,  6, 31, 
            28, 20, 24, 30,  4, 27,  3, 13, 15, 16, 14, 18,  4,  3,  8,  9, 
            20,  0, 12, 26, 21,  8, 28,  2, 29,  2, 15,  7, 11, 22, 14, 10, 
            17, 21, 12, 30, 26, 27, 16, 31, 11,  7, 13, 23, 10,  5, 22, 19 
            };
        static byte[] table_4 = { 
            15, 12, 10,  4,  1, 14, 11,  7,  5,  0, 14,  7,  1,  2, 13,  8, 
            10,  3,  4,  9,  6,  0,  3,  2,  5,  6,  8,  9, 11, 13, 15, 12 
            };
        static byte[][] table = { table_0, table_1, table_2, table_3, table_4 };

        byte[] key = new byte[16];
        Dictionary<int, int>[] badrand = new Dictionary<int, int>[8];
        Random rnd = new Random();

        public void setkey(byte[] key)
        {
            for(int i=0;i<16;i++)
                this.key[i] = key[i];
            //Do3RExperiment();

            for(int i=0;i<8;i++)
            {
                badrand[i] = find_2Rcollision_rands(key[i], key[i+8]);
            }
        }

        public static void swap(ref int m, ref int n, int j)
        {
            int y = (m + 2 * n) & ((1 << (9 - j)) - 1);
            int z = (2 * m + n) & ((1 << (9 - j)) - 1);
            m = table[j][y];
            n = table[j][z];
        }

        public static int Compute2R(int K0, int K8, int R0, int R8)
        {
            swap(ref K0, ref R0, 0);
            swap(ref K8, ref R8, 0);
            swap(ref K0, ref K8, 1);
            swap(ref R0, ref R8, 1);
            return ((K0 & 0x7F) << 21) |
                    ((K8 & 0x7F) << 14) |
                    ((R0 & 0x7F) << 7) |
                    (R8 & 0x7F);
        }

        public static long Compute3R(int K0, int K4, int K8, int K12, int R0, int R4, int R8, int R12)
        {
            swap(ref K0, ref R0, 0);
            swap(ref K4, ref R4, 0);
            swap(ref K8, ref R8, 0);
            swap(ref K12, ref R12, 0);

            swap(ref K0, ref K8, 1);
            swap(ref K4, ref K12, 1);
            swap(ref R0, ref R8, 1);
            swap(ref R4, ref R12, 1);

            swap(ref R0, ref R4, 2);
            swap(ref R8, ref R12, 2);
            swap(ref K0, ref K4, 2);
            swap(ref K8, ref K12, 2);
            return (((long)(((uint)K0) << (6 * 3) | ((uint)K4) << (6 * 2) | ((uint)K8) << (6 * 1) | ((uint)K12) << (6 * 0))) << 24) |
                    ((long)(((uint)R0) << (6 * 3) | ((uint)R4) << (6 * 2) | ((uint)R8) << (6 * 1) | ((uint)R12) << (6 * 0)));
            
            //return ((Int64)K0 & 0x3F) << (6 * 7) |
            //       ((Int64)K4 & 0x3F) << (6 * 6) |
            //       ((Int64)K8 & 0x3F) << (6 * 5) |
            //       ((Int64)K12& 0x3F) << (6 * 4) |
            //       ((Int64)R0 & 0x3F) << (6 * 3) |
            //       ((Int64)R4 & 0x3F) << (6 * 2) |
            //       ((Int64)R8 & 0x3F) << (6 * 1) |
            //       ((Int64)R12& 0x3F) << (6 * 0);
        }
        public static void Compute4R(int[] K, byte[] R, int[] Result)
        {
            long r1 = Compute3R(K[0], K[2], K[4], K[6], R[0], R[2], R[4], R[6]);
            long r2 = Compute3R(K[1], K[3], K[5], K[7], R[1], R[3], R[5], R[7]);
            for (int i = 0; i < 8; i++)
            {
                Result[2 * i] = (int)(r1 & 0x3F);
                Result[2 * i + 1] = (int)(r2 & 0x3F);
                swap(ref Result[2 * i], ref Result[2 * i + 1], 3);
                r1 >>= 6;
                r2 >>= 6;
            }
        }

        public static Dictionary<int, int> find_2Rcollision_rands(int key0, int key8)
        {
            Dictionary<int, int> collisions = new Dictionary<int, int>();
            List<KeyValuePair<int, int>> v = new List<KeyValuePair<int, int>>();
            int k0 = key0;
            int k8 = key8;
            for (int r0 = 0; r0 < 256; r0++)
                for (int r8 = 0; r8 < 256; r8++)
                    v.Add(new KeyValuePair<int, int>(r0 << 8 | r8, Compute2R(k0, k8, r0, r8)));

            v.Sort(delegate(KeyValuePair<int, int> c1, KeyValuePair<int, int> c2)
            {
                return Comparer<int>.Default.Compare(c1.Value, c2.Value);
            });

            var i = v.GetEnumerator();
            i.MoveNext();
            var prev = i.Current;
            while(i.MoveNext())
            {
                if (i.Current.Value == prev.Value)
                {
                    collisions[prev.Key] = prev.Value;
                    collisions[i.Current.Key] = i.Current.Value;
                }
                prev = i.Current;
            }

            return collisions;
        }

        /* 
        * This code derived from a leaked document from the GSM standards. 
        * Some missing pieces were filled in by reverse-engineering a working SIM. 
        * We have verified that this is the correct COMP128 algorithm. 
        * 
        * The first page of the document identifies it as 
        *      _Technical Information: GSM System Security Study_. 
        *      10-1617-01, 10th June 1988. 
        * The bottom of the title page is marked 
        *      Racal Research Ltd. 
        *      Worton Drive, Worton Grange Industrial Estate, 
        *      Reading, Berks. RG2 0SB, England. 
        *      Telephone: Reading (0734) 868601   Telex: 847152 
        * The relevant bits are in Part I, Section 20 (pages 66--67).  Enjoy! 
        * 
        * Note: There are three typos in the spec (discovered by 
        * reverse-engineering). 
        * First, "z = (2 * x[n] + x[n]) mod 2^(9-j)" should clearly read 
        * "z = (2 * x[m] + x[n]) mod 2^(9-j)". 
        * Second, the "k" loop in the "Form bits from bytes" section is severely 
        * botched: the k index should run only from 0 to 3, and clearly the range 
        * on "the (8-k)th bit of byte j" is also off (should be 0..7, not 1..8, 
        * to be consistent with the subsequent section). 
        * Third, SRES is taken from the first 8 nibbles of x[], not the last 8 as 
        * claimed in the document.  (And the document doesn't specify how Kc is 
        * derived, but that was also easily discovered with reverse engineering.) 
        * All of these typos have been corrected in the following code. 
        */
        public byte[] A3A8(/* in */ byte[] rand, bool collision_2r_proof = true)
        {
            //byte[] p = {9, 11, 14 , 2 ,3, 7, 15, 10, 1, 0 ,4 ,8, 12, 6, 5, 13}; 
                        //15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
            byte[] simoutput = new byte[12];
            byte[] x = new byte[32];
            byte[] bit = new byte[128];
            int i, j, k, l, m, n, y, z, next_bit;

            byte[] fake_key = new byte[16];
            //Test for bad rands
            for (i = 0; i < 8; i++)
            {
                int r = (rand[i] << 8) | rand[i + 8];
                if (badrand[i].ContainsKey(r) && collision_2r_proof)
                {
                    fake_key[i] = fake_key[i + 8] = 12;
                    //Console.Write("F");
                    byte[] faker = new byte[12];
                    rnd.NextBytes(faker);
                    return faker;
                }
                else
                    fake_key[i] = fake_key[i + 8] = 0;
            }
                /* ( Load RAND into last 16 bytes of input ) */
                for (i = 16; i < 32; i++)
                    x[i] = rand[i - 16];

            /* ( Loop eight times ) */
            for (i = 1; i < 9; i++)
            {
                /* ( Load key into first 16 bytes of input ) */
                for (j = 0; j < 16; j++)
                    x[j] = (byte)(key[j] + fake_key[j]);
                /* ( Perform substitutions ) */
                for (j = 0; j < 5; j++)
                    for (k = 0; k < (1 << j); k++)
                        for (l = 0; l < (1 << (4 - j)); l++)
                        {
                            m = l + k * (1 << (5 - j));
                            n = m + (1 << (4 - j));
                            y = (x[m] + 2 * x[n]) % (1 << (9 - j));
                            z = (2 * x[m] + x[n]) % (1 << (9 - j));
                            x[m] = table[j][y];
                            x[n] = table[j][z];
                        }
                /* ( Form bits from bytes ) */
                for (j = 0; j < 32; j++)
                    for (k = 0; k < 4; k++)
                        bit[4 * j + k] = (byte)((x[j] >> (3 - k)) & 1);
                /* ( Permutation but not on the last loop ) */
                if (i < 8)
                    for (j = 0; j < 16; j++)
                    {
                        x[j + 16] = 0;
                        for (k = 0; k < 8; k++)
                        {
                            next_bit = ((8 * j + k) * 17) % 128;
                            x[j + 16] |= (byte)(bit[next_bit] << (7 - k));
                        }
                    }
            }

            /* 
             * ( At this stage the vector x[] consists of 32 nibbles. 
             *   The first 8 of these are taken as the output SRES. ) 
             */

            /* The remainder of the code is not given explicitly in the 
             * standard, but was derived by reverse-engineering. 
             */

            for (i = 0; i < 4; i++)
                simoutput[i] = (byte)((x[2 * i] << 4) | x[2 * i + 1]);
            for (i = 0; i < 6; i++)
                simoutput[4 + i] = (byte)((x[2 * i + 18] << 6) | (x[2 * i + 18 + 1] << 2)
                                | (x[2 * i + 18 + 2] >> 2));
            simoutput[4 + 6] = (byte)((x[2 * 6 + 18] << 6) | (x[2 * 6 + 18 + 1] << 2));
            simoutput[4 + 7] = 0;
            return simoutput;
        }

        public void Break()
        {
            byte[] s = new byte[16];
            rnd.NextBytes(s);
            s[0] = s[4] = s[8] = s[12] = 0;
            Dictionary<ulong, uint> seen = new Dictionary<ulong, uint>();
            int key_candidates = 0;
            for (uint i = 0; i < 0xFFFFFFFF; i++)
            {
                s[0] = (byte)i;
                s[8] = (byte)(i >> 8);
                s[4] = (byte)(i >> 16);
                s[12] = (byte)(i >> 24);
                byte[] r = A3A8(s);
                ulong index = ((ulong)r[0]) | ((ulong)r[1] << 8) | ((ulong)r[2] << 16) | ((ulong)r[3] << 24)
                                | ((ulong)r[4] << 32) | ((ulong)r[5] << 40) | ((ulong)r[6] << 48) | ((ulong)r[7] << 56);
                if (seen.ContainsKey(index))
                {
                    Console.WriteLine(String.Format("Find collision after {0} steps.", i));
                    uint j = seen[index];
                    byte r0_0 = (byte)(i & 0xFF);
                    byte r8_0 = (byte)((i>>8) & 0xFF);
                    byte r4_0 = (byte)((i>>16) & 0xFF);
                    byte r12_0 = (byte)((i>>24) & 0xFF);
                    byte r0_1 = (byte)(j & 0xFF);
                    byte r8_1 = (byte)((j>>8) & 0xFF);
                    byte r4_1 = (byte)((j>>16) & 0xFF);
                    byte r12_1 = (byte)((j>>24) & 0xFF);

                    s[0] = r0_0; s[4] = r4_0; s[8] = r8_0; s[12] = r12_0;
                    for (j = 0; j < 16; j++) Console.Write(String.Format("{0:X02} ", s[j])); Console.WriteLine();
                    r = A3A8(s);
                    for (j = 0; j < 12; j++) Console.Write(String.Format("{0:X02} ", r[j])); Console.WriteLine();

                    s[0] = r0_1; s[4] = r4_1; s[8] = r8_1; s[12] = r12_1;
                    for (j = 0; j < 16; j++) Console.Write(String.Format("{0:X02} ", s[j])); Console.WriteLine();
                    r = A3A8(s);
                    for (j = 0; j < 12; j++) Console.Write(String.Format("{0:X02} ", r[j])); Console.WriteLine();
                    var m = Compute2R(key[0], key[8], r0_0, r8_0);
                    var n = Compute2R(key[0], key[8], r0_1, r8_1);
                    var x = Compute3R(key[0], key[4], key[8], key[12], r0_0, r4_0, r8_0, r12_0);
                    var y = Compute3R(key[0], key[4], key[8], key[12], r0_1, r4_1, r8_1, r12_1);
                    Console.WriteLine(String.Format("2R: {0:X8} 3R: {1:X16}", m^n, x^y));
                    Console.WriteLine(String.Format("Real Key: {0:x2} {1:x2} {2:x2} {3:x2}",
                        new object[] { key[0], key[4], key[8], key[12] }));

                    //Sort all possible K0 K8 pair in ascending order of their 2R's hamming distance and try in that order.
                    List<KeyValuePair<int, int>> K08 = new List<KeyValuePair<int, int>>();
                    for (int k0 = 0; k0 <= 0xFF; k0++)
                        for (int k8 = 0; k8 <= 0xFF; k8++)
                            K08.Add(new KeyValuePair<int,int>((k0<<8) | k8, Compute2R(k0, k8, r0_0, r8_0) ^ Compute2R(k0, k8, r0_1, r8_1)));
                    K08.Sort(new IntComparer<KeyValuePair<int, int>>(v => HammingDistance.long_hamming(v.Value)));

                    foreach (var k08 in K08)
                    {
                        int k0 = (k08.Key >> 8) & 0xFF;
                        int k8 = (k08.Key >> 0) & 0xFF;
                        //SOrt K4 K12 in ascending order of 3R
                        List<KeyValuePair<int, long>> K412 = new List<KeyValuePair<int, long>>();
                        for (int k4 = 0; k4 <= 0xFF; k4++)
                            for (int k12 = 0; k12 <= 0xFF; k12++)
                                K412.Add(new KeyValuePair<int, long>((k4 << 8) | k12, 
                                    Compute3R(k0, k4, k8, k12, r0_0, r4_0, r8_0, r12_0) ^ 
                                    Compute3R(k0, k4, k8, k12, r0_0, r4_0, r8_0, r12_0)
                                    ));
                        K412.Sort(new IntComparer<KeyValuePair<int, long>>(v => HammingDistance.long_hamming(v.Value)));
                        foreach (var k412 in K412)
                        {
                            int k4 = (k412.Key >> 8) & 0xFF;
                            int k12 = (k412.Key >> 0) & 0xFF;
                            if (Compute3R(k0, k4, k8, k12, r0_0, r4_0, r8_0, r12_0) ==
                                Compute3R(k0, k4, k8, k12, r0_1, r4_1, r8_1, r12_1))
                            {
                                Console.WriteLine(String.Format("Calced Key: {0:x2} {1:x2} {2:x2} {3:x2}",
                                    new object[] { k0, k4, k8, k12 }));
                                key_candidates++;
                            }
                        }
                    }
                    break;
                }
                else
                    seen[index] = i;
            }
            Console.WriteLine(String.Format("Found {0} possible keys.", key_candidates));
        }

    }

}