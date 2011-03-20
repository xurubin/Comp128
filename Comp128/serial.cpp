#include <windows.h>
#include <assert.h>
#include <stdio.h>

void PrintError( LPCSTR str)
{
	LPVOID lpMessageBuffer;
	int error = GetLastError();
	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		error,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), //The user default language
		(LPTSTR) &lpMessageBuffer,
		0,
		NULL
		);
	printf("%s: (%d) %s\n\n",str,error,lpMessageBuffer);
	LocalFree( lpMessageBuffer );
}

unsigned char ReadByte(HANDLE h)
{
	unsigned char data = 0;
	DWORD len = 0;
	if (!ReadFile(h, &data, 1, &len,  NULL))
		printf("ReadFile error.");
	if (len != 1)
		printf("ReadFile error2.");
	return data;
}

void WriteBuffer(HANDLE h, unsigned char* buf, int len)
{
	DWORD written = 0;
	if (!WriteFile(h, buf, len, &written, NULL))
		printf("WriteFile error.");
	if (written != len)
		printf("WriteFile error2.");
	FlushFileBuffers(h);
}

int main(int argc, char* argv[])
{
	// open port for I/O
	HANDLE h = CreateFile("COM8",
		GENERIC_READ|GENERIC_WRITE,
		0,NULL,
		OPEN_EXISTING,0,NULL);

	if(h == INVALID_HANDLE_VALUE) {
		PrintError("E012_Failed to open port");
	} else {
		// set timeouts
		COMMTIMEOUTS cto = { MAXDWORD, MAXDWORD, MAXDWORD, MAXDWORD, MAXDWORD };
		DCB dcb;
		if(!SetCommTimeouts(h,&cto))
			PrintError("E013_SetCommTimeouts failed");

		// set DCB
		memset(&dcb,0,sizeof(dcb));
		dcb.DCBlength = sizeof(dcb);
		dcb.BaudRate = 9600;
		dcb.fBinary = 1;
		dcb.fDtrControl = DTR_CONTROL_ENABLE;
		dcb.fRtsControl = RTS_CONTROL_ENABLE;
		// dcb.fOutxCtsFlow = 1;
		// dcb.fRtsControl = DTR_CONTROL_HANDSHAKE;

		dcb.Parity = NOPARITY;
		dcb.StopBits = ONESTOPBIT;
		dcb.ByteSize = 8;

		if(!SetCommState(h,&dcb))
			PrintError("E014_SetCommState failed");

		//Wait for Reset Signal
		printf("Waiting for DSR == 1\n");
		DWORD CommState = 0;
		do{
			GetCommModemStatus(h, &CommState); 
		} while( (CommState & MS_DSR_ON) == 0);

		//Send ATR 
		Sleep(500);
		printf("Sending ATR\n");
		unsigned char ATR[] = {0x3B, 0x97, 0x11, 0x00, 0x02, 0x02, 0x03, 0x15, 0x00, 0x33, 0x02};
		WriteBuffer(h, ATR, 11);

		unsigned char APDU_Completed[] = {0x90, 0x00};
		unsigned char APDU_MoreData[] = {0x9F, 0x00};

		unsigned char Response[256+2];
		int ResponseLen = 0;
		while(1)
		{
			printf("Waiting..");
			unsigned char cla = ReadByte(h);
			printf(",");
			while (cla != 0xA0) 
			{ 
				printf("Resyncing cla, got %.2x.", cla);
				cla = (byte)ReadByte(h); 
			}
			unsigned char ins = ReadByte(h);
			printf(",");
			unsigned char p1 = ReadByte(h);
			printf(",");
			unsigned char p2 = ReadByte(h);
			printf(",");
			unsigned char p3 = ReadByte(h);
			printf(",");
			printf("Incoming - %.2x, %.2x, %.2x, %.2x ",  ins, p1, p2, p3 );
			int fileid, b1, b2;
			switch (ins)
			{
			case 0xA4:
				printf("Select ");
				assert((p1 == 0) && (p2 == 0) && (p3 == 2));
				b1 = ReadByte(h);
				printf(",");
				b2 = ReadByte(h);
				printf(",");
				fileid = b1 * 256 + b2;
				printf("%.4x\n", fileid);
				if (fileid == 0x7F20 || fileid == 0x7F10 || fileid == 0x7F21)
					ResponseLen = 0x16;
				else
					ResponseLen = 0xF;
				APDU_MoreData[1] = ResponseLen;
				WriteBuffer(h, APDU_MoreData, 2);
				break;
			case 0x88:
				printf("Run_GSM\n");
				assert((p1 == 0) && (p2 == 0) && (p3 == 0x10));
				printf("Rand: ");
				for (int i = 0; i < p3; i++)
				{
					Response[i] = (byte)ReadByte(h);
					printf("%.2x ", Response[i]);
				}

				printf("\n");
				APDU_MoreData[1] = 0xC;
				WriteBuffer(h, APDU_MoreData, 2);
				ResponseLen = 0xC;
				Response[0]++;
				break;
			case 0xC0:
				printf("Get_Response len: %.2x\n", p3);
				//Debug.Assert(ResponseLen >= p3);
				//ComPort.Write(new byte[] { ins }, 0, 1);
				WriteBuffer(h, Response, p3);
				Sleep(50);
				WriteBuffer(h, APDU_Completed, 2);
				break;
			case 0xB0:
				printf("Read_Binary\n");
				//ComPort.Write(new byte[] { ins }, 0, 1);
				Response[0]++;
				WriteBuffer(h, Response, p3 == 0 ? 256 : p3);
				Sleep(50);
				WriteBuffer(h, APDU_Completed, 2);
				break;
			case 0xB2:
				printf("Read_Record\n");
				//ComPort.Write(new byte[] { ins }, 0, 1);
				Response[0]++;
				WriteBuffer(h, Response, p3 == 0 ? 256 : p3);
				Sleep(50);
				WriteBuffer(h, APDU_Completed, 2);
				break;
			case 0x44:
				printf("Rehabilitate\n");
				// ComPort.Write(new byte[] { ins }, 0, 1);
				WriteBuffer(h, APDU_Completed, 2);
				break;
			default:
				printf("%.2x\n", ins & 0xFF);
				WriteBuffer(h, APDU_Completed, 2);
				break;
			}
		}

		while (true)
		{
			//printf(String.Format("{0:X02}", b & 0xFF));
		}

		CloseHandle(h);
	}
}
