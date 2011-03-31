using System;
using System.Collections.Generic;
using System.Text;
using System.IO.Ports;
using System.Threading;
using System.Diagnostics;

namespace SIMEmu
{
    class Program
    {
        static SerialPort ComPort;

        static byte ReadByte(SerialPort Com)
        {
            byte b = (byte)Com.ReadByte();
            //Console.Write(",");
            Com.Write(new byte[] { b }, 0, 1);
            return b;
        }

        static byte[] KI = {0x54, 0x65, 0x13, 0x82, 0x41, 0x85, 0x79, 0x52,
                            0x35, 0x54, 0x44, 0x63, 0x19, 0x75, 0x84, 0x5A};

        static void ComEmulator()
        {
            Comp128 GSMAlgo = new Comp128();
            Random rnd = new Random();
            //while (true)
            {
                byte[] tki = new byte[16];
                rnd.NextBytes(tki);
                GSMAlgo.setkey(tki);
                GSMAlgo.Break();
            }
            //Init COM Port interface
            ComPort = new SerialPort("COM8");
            ComPort.BaudRate = 9600;
            ComPort.Parity = Parity.None;
            ComPort.Handshake = Handshake.None;
            ComPort.StopBits = StopBits.One;
            ComPort.DataBits = 8;
            ComPort.ReadTimeout = SerialPort.InfiniteTimeout;
            ComPort.WriteTimeout = SerialPort.InfiniteTimeout;
            ComPort.Open();
            ComPort.DiscardInBuffer();
            ComPort.DiscardOutBuffer();
            Thread t = new Thread(delegate()
            {
                while (true)
                {
                    Console.WriteLine(String.Format("{0} {1} {2}", ComPort.DsrHolding ? 1 : 0, ComPort.CtsHolding ? 1 : 0, ComPort.CDHolding ? 1 : 0));
                }
            });

            //t.Start();
            while (true)
            {
                Console.WriteLine("Waiting for DSR == 1"); while (ComPort.DsrHolding == false) ;
                //Console.WriteLine("Waiting for RTS(CTS) == 0"); while (ComPort.CtsHolding) ;
                Thread.Sleep(700);
                Console.WriteLine("Sending ATR");
                ComPort.Write(new byte[] { 0x3B, 0x2F, 0x00, 0x80, 0x69, 0xAF, 0x02, 0x04, 0x01, 0x36, 0x00, 0x00, 0x0A, 0x0E, 0x83, 0x3E, 0x9F, 0x16 }, 0, 0x12);
                byte[] Response = new byte[256 + 2];
                byte[] Rand = new byte[16];
                byte ResponseLen = 0;
                while (ComPort.DsrHolding)
                {
                    Console.Write("Waiting..");
                    ComPort.ReadTimeout = 500;
                    byte cla = 0;
                    do
                    {
                        try
                        {
                            cla = ReadByte(ComPort);
                        }
                        catch (TimeoutException)
                        {
                            if (!ComPort.DsrHolding) break;
                        }
                        if (cla != 0xA0)
                            Console.Write(".");
                    } while (cla != 0xA0);
                    ComPort.ReadTimeout = SerialPort.InfiniteTimeout;
                    if (!ComPort.DsrHolding) break;

                    byte ins = ReadByte(ComPort);
                    byte p1 = ReadByte(ComPort);
                    byte p2 = ReadByte(ComPort);
                    byte p3 = ReadByte(ComPort);
                    Console.Write(String.Format(" - {0:X02}, {1:X02}, {2:X02}, {3:X02} ", new object[] { ins, p1, p2, p3 }));
                    ComPort.Write(new byte[] { ins }, 0, 1);
                    switch (ins)
                    {
                        case 0xA4:
                            Console.Write("Select ");
                            Debug.Assert(p1 == 0 && p2 == 0 && p3 == 2);
                            byte b1 = ReadByte(ComPort);
                            byte b2 = ReadByte(ComPort);
                            int fileid = b1 * 256 + b2;
                            Console.WriteLine(String.Format("{0:X04}", fileid));
                            if (fileid == 0x7F20 || fileid == 0x7F10 || fileid == 0x7F21)
                                ResponseLen = 0x16;
                            else
                                ResponseLen = 0xF;
                            Response[13] |= 0x80;
                            ComPort.Write(new byte[] { 0x9F, ResponseLen }, 0, 2);
                            break;
                        case 0x88:
                            Console.WriteLine("Run_GSM");
                            Debug.Assert(p1 == 0 && p2 == 0 && p3 == 0x10);
                            Console.Write("Rand: ");
                            for (int i = 0; i < p3; i++)
                            {
                                Rand[i] = ReadByte(ComPort);
                                Console.Write(String.Format("{0:X02} ", Rand[i]));
                            }

                            Console.WriteLine();
                            ComPort.Write(new byte[] { 0x9F, 0xC }, 0, 2);
                            byte[] sres = GSMAlgo.A3A8(Rand);
                            ResponseLen = 0xC;
                            for (int i = 0; i < 12; i++) Response[i] = sres[i];
                            break;
                        case 0xC0:
                            Console.WriteLine("Get_Response");
                            //Debug.Assert(ResponseLen >= p3);
                            //ComPort.Write(new byte[] { ins }, 0, 1);
                            ComPort.Write(Response, 0, p3);
                            //Thread.Sleep(50);
                            ComPort.Write(new byte[] { 0x90, 0x0 }, 0, 2);
                            break;
                        case 0xB0:
                            Console.WriteLine("Read_Binary");
                            //ComPort.Write(new byte[] { ins }, 0, 1);
                            Response[0] = 0x12;
                            ComPort.Write(Response, 0, p3 == 0 ? 256 : p3);
                            //Thread.Sleep(50);
                            ComPort.Write(new byte[] { 0x90, 0x0 }, 0, 2);
                            break;
                        case 0xB2:
                            Console.WriteLine("Read_Record");
                            //ComPort.Write(new byte[] { ins }, 0, 1);
                            Response[0] = 0x34;
                            ComPort.Write(Response, 0, p3 == 0 ? 256 : p3);
                            //Thread.Sleep(50);
                            ComPort.Write(new byte[] { 0x90, 0x0 }, 0, 2);
                            break;
                        case 0x44:
                            Console.WriteLine("Rehabilitate");
                            // ComPort.Write(new byte[] { ins }, 0, 1);
                            ComPort.Write(new byte[] { 0x90, 0x0 }, 0, 2);
                            break;
                        default:
                            Console.Write(String.Format("Unknown INS: {0:X02}", ins & 0xFF));
                            ComPort.Write(new byte[] { 0x90, 0x0 }, 0, 2);
                            break;
                    }
                    //Console.Write(String.Format("{0:X02}", b & 0xFF));
                }
            }
        }

        class TestA38 : IComp128Impl
        {
            Random rnd = new Random(123);
            Comp128 a38 = new Comp128();
            public void Renew()
            {
                byte[] b = new byte[16];// {?? 0xAB, ?? 0x6D, ?? 0xA0, ?? 0xA2, ?? 0x7D, ?? 0x8C, ?? 0xF1, ?? 0x2C};
                rnd.NextBytes(b);
                b[1] = 0xab; b[5] = 0xa0; 
                b[9] = 0x7d; b[13] = 0xf1;
                Console.Write("Private Key: ");
                for (int j = 0; j < 16; j++) Console.Write(String.Format("{0:X02} ", b[j])); Console.WriteLine();
                a38.setkey(b);
            }


            public bool A38(byte[] Rand, byte[] Result)
            {
                a38.A3A8(Rand).CopyTo(Result, 0);
                return true;
            }
        }

        static void Main(string[] args)
        {
            int[] ct = new int[1<<7];
            for (int x0 = 0; x0 < (1 << 7); x0++)
                for (int d = 0; d < (1 << 7); d++)
                {
                    int x1 = (x0 + d) % (1<<7);
                    if (x0 == x1) continue;
                    int collide_count = 0;
                    for (int y = 0; y < (1 << 7); y++)
                    {
                        int x0_ = x0, x1_ = x1, y0 = y, y1 = y;
                        Comp128.swap(ref x0_, ref y0, 2);
                        Comp128.swap(ref x1_, ref y1, 2);
                        if (x0_ == x1_ && y0 == y1) collide_count++;
                    }
                    ct[d] += collide_count;
                    if (collide_count < 1) continue;
                   // Console.WriteLine(String.Format("{0:X2}{1:X2} Collision count: {2}", x0, d, collide_count));
                }
            for(int d=0;d<(1<<7);d++)
                                    Console.WriteLine(String.Format("{0:X2} Collision count: {1}", d, ct[d]));

            if (args.Length > 0)
            {
                CrackSIM(new SIMInterface(), args[0]);
                return;
            }
            TestA38 t = new TestA38();
            t.Renew();
            CrackSIM(t, "session.dat");
        }

        static void CrackSIM(IComp128Impl sim, string sessionfile)
        {
            Comp128Cracker b = new Comp128Cracker(sim);
            bool new_session = b.InitNewSession(sessionfile);
            b.Attack5R(new int[] { 0xAB, 0xAA, 0xA0, 0x9F, 0x7D, 0x05, 0xF1, 0x28 });
            if (new_session || ((!new_session) && (b.RestoreSession(sessionfile))))
            {
                //b.Attack4R(0xab, 0xa0, 0x7d, 0xf1);
                b.Start();
                Console.ReadKey(true);
                b.Stop();
            }
            else
            {
                Console.WriteLine("Fail to InitNewSession or RestoreSession.");
                Console.ReadKey(true);
            }
        }
    }
}
