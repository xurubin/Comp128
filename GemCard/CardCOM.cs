using System;
using System.Runtime.InteropServices;
using SCARDSSPLib;
using GemCardExLib;

namespace GemCard
{
	/// <summary>
	/// Implements the ICard interface using the SCard COM objects from Microsoft and SCardDatabaseEx object
	/// for the ListReaders function.
	/// </summary>
	public class CardCOM : CardBase
	{
		private ISCard	m_itfCard = null;

		/// <summary>
		/// Default constructor
		/// </summary>
		public CardCOM()
		{
			// Create the SCard object
			m_itfCard = new CSCardClass();
		}

		#region ICard Members

		/// <summary>
		/// Wraps the PCSC function
		/// LONG SCardListReaders(SCARDCONTEXT hContext, 
		///		LPCTSTR mszGroups, 
		///		LPTSTR mszReaders, 
		///		LPDWORD pcchReaders 
		///	);
		/// </summary>
		/// <returns>A string array of the readers</returns>
		public	override string[]	ListReaders()
		{
			ISCardDatabaseEx itfCardBase = new SCardDatabaseEx();

			return (string[]) itfCardBase.ListReaders();
		}

		/// <summary>
		///  Wraps the PCSC function
		///  LONG SCardConnect(
		///		IN SCARDCONTEXT hContext,
		///		IN LPCTSTR szReader,
		///		IN DWORD dwShareMode,
		///		IN DWORD dwPreferredProtocols,
		///		OUT LPSCARDHANDLE phCard,
		///		OUT LPDWORD pdwActiveProtocol
		///	);
		/// </summary>
		/// <param name="Reader"></param>
		/// <param name="ShareMode"></param>
		/// <param name="PreferredProtocols"></param>
		public override void Connect(string Reader, SHARE ShareMode, PROTOCOL PreferredProtocols)
		{
			// Calls AttachReader to connect to the card
			m_itfCard.AttachByReader(Reader, (SCARD_SHARE_MODES) ShareMode, (SCARD_PROTOCOLS) PreferredProtocols);
		}

		/// <summary>
		/// Wraps the PCSC function
		///	LONG SCardDisconnect(
		///		IN SCARDHANDLE hCard,
		///		IN DWORD dwDisposition
		///	);
		/// </summary>
		/// <param name="Disposition"></param>
		public override void Disconnect(DISCONNECT Disposition)
		{
			// Off the connection with the card
			m_itfCard.Detach((SCARD_DISPOSITIONS) Disposition);
		}

		/// <summary>
		/// Wraps the PCSC function
		/// LONG SCardTransmit(
		///		SCARDHANDLE hCard,
		///		LPCSCARD_I0_REQUEST pioSendPci,
		///		LPCBYTE pbSendBuffer,
		///		DWORD cbSendLength,
		///		LPSCARD_IO_REQUEST pioRecvPci,
		///		LPBYTE pbRecvBuffer,
		///		LPDWORD pcbRecvLength
		///	);
		/// </summary>
		/// <param name="ApduCmd">APDUCommand object with the APDU to send to the card</param>
		/// <returns>An APDUResponse object with the response from the card</returns>
		public override APDUResponse Transmit(APDUCommand ApduCmd)
		{
			CSCardCmd	itfCmd = new CSCardCmdClass();
			CByteBuffer	itfData = new CByteBufferClass();
			int	nLe = ApduCmd.Le;

			if (ApduCmd.Data == null)
			{
				itfData.SetSize(0);
			}
			else
			{
				int nWrite = 0;

				itfData.SetSize(ApduCmd.Data.Length);
				itfData.Write(ref ApduCmd.Data[0], ApduCmd.Data.Length, ref nWrite);
			}

			// Build the APDU command
			itfCmd.BuildCmd(ApduCmd.Class, ApduCmd.Ins, ApduCmd.P1, ApduCmd.P2, itfData, ref nLe);

			// Send the command
			m_itfCard.Transaction(ref itfCmd);

			// Analyse the response
			int nRead = 0;
			byte[]	pbResp = new byte[itfCmd.ApduReplyLength];

			itfCmd.ApduReply.Read(ref pbResp[0], itfCmd.ApduReplyLength, ref nRead);

			return new APDUResponse(pbResp);
		}

        /// <summary>
        /// Wraps the PSCS function
        /// LONG SCardBeginTransaction(
        ///     SCARDHANDLE hCard
        //  );
        /// This function is not supported in the COM implementation
        /// </summary>
        public override void BeginTransaction()
        {
            throw new NotImplementedException("BeginTransaction is not supported in the COM implementation");
        }

        /// <summary>
        /// Wraps the PCSC function
        /// LONG SCardEndTransaction(
        ///     SCARDHANDLE hCard,
        ///     DWORD dwDisposition
        /// );
        /// This function is not supported in the COM implementation
        /// </summary>
        /// <param name="Disposition">A value from DISCONNECT enum</param>
        public override void EndTransaction(DISCONNECT Disposition)
        {
            throw new NotImplementedException("EndTransaction is not supported in the COM implementation");
        }

        /// <summary>
        /// Gets the attributes of the card
        /// </summary>
        /// <param name="AttribId">Identifier for the Attribute to get</param>
        /// <returns>Attribute content</returns>
        public override byte[] GetAttribute(UInt32 AttribId)
        {
            throw new NotImplementedException();
        }
        #endregion

        /// <summary>
        /// This function must implement a card detection mechanism.
        /// 
        /// When card insertion is detected, it must call the method CardInserted()
        /// When card removal is detected, it must call the method CardRemoved()
        /// 
        /// </summary>
        protected override void RunCardDetection(object Reader)
        {
            throw new Exception("The method or operation is not implemented.");
        }
	}
}
