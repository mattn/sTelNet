/******************************************************************************
* sTelNet - Small Telnet Program For WIN32
*                                              2001/06/22 Created By �܂���
*------------------------------------------------------------------------------
* vim:set ts=4 nowrap:
******************************************************************************/

//#define DEBUG_TXT             /* �o�͕����̃f�o�b�O   */
//#define DEBUG_CTX             /* ���䕶���̃f�o�b�O   */
//#define DEBUG_ESC             /* �G�X�P�[�v�̃f�o�b�O */
//#define DEBUG_NTA             /* NTLM�F�؂̃f�o�b�O   */
//#define DEBUG_RCV             /* ��M�f�[�^�̃f�o�b�O */
//#define DEBUG_SND             /* ���M�f�[�^�̃f�o�b�O */
#define DEBUG_SCK				/* �\�P�b�g�̃f�o�b�O   */

#define SUPPORT_WSK2			/* Winsock2 �̃T�|�[�g  */
#define SUPPORT_SERV			/* �T�[�o�@�\�̃T�|�[�g */
#define SUPPORT_SWAP			/* ����p��ʂ̃T�|�[�g */
#define SUPPORT_NAWS			/* NAWS�̃T�|�[�g       */
#define SUPPORT_GPMP			/* GPM�̃T�|�[�g        */
#define SUPPORT_SYMB			/* SYMBOL�̃T�|�[�g     */
#define SUPPORT_PIPE			/* �p�C�v�̃T�|�[�g     */
#define SUPPORT_ICON			/* �A�C�R���̃T�|�[�g   */
#define SUPPORT_JPNK			/* ���{��̃T�|�[�g     */
#define SUPPORT_NTLM			/* NTLM�̃T�|�[�g       */
#define SUPPORT_SPRT			/* �V���A���̃T�|�[�g   */
//#define SUPPORT_RBUF          /* ��M�X�v�[���T�|�[�g */

/* GNUC �ł͌��� NTLM �̓T�|�[�g�ł��Ȃ� */
#ifdef __GNUC__
# ifdef SUPPORT_NTLM
#  warning "Can't support NTLM on GNUC"
#  undef SUPPORT_NTLM
# endif
#endif

/******************************************************************************
* Includes
******************************************************************************/
#ifdef SUPPORT_WSK2
# include <winsock2.h>
#else
# include <winsock.h>
# ifndef SD_BOTH
#  define SD_BOTH 0x02
# endif
#endif

#include <windows.h>
#include <process.h>
#include <stdio.h>
#ifdef SUPPORT_NTLM
# define SECURITY_WIN32
# include <sspi.h>
# ifndef SEC_I_COMPLETE_NEEDED
#  include <issperr.h>
# endif
#endif

/******************************************************************************
* definitions
******************************************************************************/
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"user32.lib")
#ifdef SUPPORT_ICON
# pragma comment(lib,"shell32.lib")
#endif
#ifndef _MT
//#error "Compile with MT option!"
#endif

#ifndef U_CHAR
typedef unsigned char U_CHAR;
#endif

/* �L�[�A�T�C���\���� */
typedef struct
{
	WORD key;
	U_CHAR *esc1;
	U_CHAR *esc2;
}
KEY_STRUCT, *LPKEY_STRUCT;

/* ���{���ލ\���� */
typedef struct
{
	CHAR *name;					/* ��ޖ� */
	CHAR key;					/* ��ރR�[�h */
}
JAPANESE_STRUCT, *LPJAPANESE_STRUCT;

/* �ʐM�p�����\���� */
typedef struct
{
	SOCKET sock;				/* �\�P�b�g */
	HANDLE stdi;				/* �W�����̓n���h�� */
	HANDLE stdo;				/* �W���o�̓n���h�� */
	HANDLE alto;				/* �Q��ʖ� */
	USHORT serv_port;			/* �T�[�o�|�[�g */
	BOOL lock;					/* �\�P�b�g���b�N */

	BOOL vt100;					/* vt100 */
	BOOL mouse;					/* �}�E�X */
	BOOL ntlm;					/* NTLM�F�� */
	CHAR *term;					/* �[���� */
	BOOL insert;				/* �}����� */
	BOOL cursor;				/* �J�[�\����� */
#ifdef SUPPORT_JPNK
	CHAR kanji;					/* ������� */
#endif
	BOOL echo;					/* �G�R�[��� */
	CHAR line;					/* ���s��� */
	INT curp;					/* ���ݍs */
#ifdef SUPPORT_JPNK
	CHAR ime;					/* IME��� */
#endif
	BOOL bell;					/* �x����� */
#ifdef SUPPORT_NAWS
	CHAR naws;					/* NAWS��� */
#endif
}
TELNET_STRUCT, *LPTELNET_STRUCT;

/* ������� */
#define KANJI_NONE	0
#define KANJI_START 1
#define KANJI_SJIS	1
#define KANJI_JIS7	2
#define KANJI_EUCJ	3
#define KANJI_END   3
#define KANJI_KANA	4

/* �s��� */
#define LINE_NONE   0
#define LINE_CR     1
#define LINE_LF     2
#define LINE_CRLF   3
#define LINE_AUTO   4

/* NAWS��� */
#define NAWS_OFF    0
#define NAWS_ON     1
#define NAWS_AUTO   2

#define SYMBOL_NO	0
#define SYMBOL_SC	1
#define SYMBOL_GL	2

/* �F�萔 */
#ifndef FOREGROUND_WHITE
#define FOREGROUND_WHITE (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)
#endif
#ifndef BACKGROUND_WHITE
#define BACKGROUND_WHITE (BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_BLUE)
#endif
#ifndef FOREGROUND_BLACK
#define FOREGROUND_BLACK	FOREGROUND_INTENSITY
#endif
#ifndef BACKGROUND_BLACK
#define BACKGROUND_BLACK	BACKGROUND_INTENSITY
#endif
#ifndef FOREGROUND_MASK
#define FOREGROUND_MASK (FOREGROUND_RED|FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_INTENSITY)
#endif
#ifndef BACKGROUND_MASK
#define BACKGROUND_MASK (BACKGROUND_RED|BACKGROUND_BLUE|BACKGROUND_GREEN|BACKGROUND_INTENSITY)
#endif

#define RECV_BUFSIZ	4096

#define  UC(b)       (((int)b)&0xFF)

/* IME�p�G���A�̊m�� */
#ifdef SUPPORT_JPNK
# define RESTORE_IME(lpts,csbi) \
	if(lpts->ime) \
	{ \
		csbi.srWindow.Bottom--; \
	}
# define RESERVE_IME(lpts,csbi) \
	if(lpts->ime) \
	{ \
		csbi.srWindow.Bottom++; \
	}
#else
# define RESTORE_IME(lpts,csbi)
# define RESERVE_IME(lpts,csbi)
#endif

#ifdef SUPPORT_ICON
#ifdef __BORLANDC__
typedef HWND(__stdcall * GETCONSOLEWINDOWPROC) (VOID);
#else
typedef WINBASEAPI HWND(WINAPI * GETCONSOLEWINDOWPROC) (VOID);
#endif
#endif

/******************************************************************************
* Variables
******************************************************************************/
/* �L�[�ϊ��e�[�u�� */
KEY_STRUCT ks[] = {
	VK_END, "\x1bOF", "\x1bOq",
	VK_HOME, "\x1bOH", "\x1bOW",
	VK_UP, "\x1b[A", "\x1b[A",
	VK_DOWN, "\x1b[B", "\x1b[B",
	VK_RIGHT, "\x1b[C", "\x1b[C",
	VK_LEFT, "\x1b[D", "\x1b[D",
	VK_INSERT, "\x1b[2~", "\x1bOp",
	VK_DELETE, "\x1b[3~", "\x1bOn~",
	VK_PRIOR, "\x1b[5~", "\x1bOy",
	VK_NEXT, "\x1b[6~", "\x1bOs",
	VK_F1, "\x1bOP~", "\x1b[11~~",
	VK_F2, "\x1bOQ~", "\x1b[12~",
	VK_F3, "\x1bOR~", "\x1b[13~~",
	VK_F4, "\x1bOS~", "\x1b[14~~",
	VK_F5, "\x1b[15~", "\x1bOt",
	VK_F6, "\x1b[17~", "\x1bOu",
	VK_F7, "\x1b[18~", "\x1bOv",
	VK_F8, "\x1b[19~", "\x1bOw",
	VK_F9, "\x1b[20~", "\x1bOx",
	VK_F10, "\x1b[21~", "\x1bOy",
	VK_F11, "\x1b[23~", "\x1b[23~",
	VK_F12, "\x1b[24~", "\x1b[24~",
	0, NULL, NULL
};

#ifdef SUPPORT_JPNK
/* ���{���ރe�[�u�� */
JAPANESE_STRUCT js[] = {
	"sjis", KANJI_SJIS,
	"jis7", KANJI_JIS7,
	"eucj", KANJI_EUCJ,
	"none", KANJI_NONE,
};
#endif

/* NTLM�F�ؗp�O���ϐ� */
#ifdef SUPPORT_NTLM
HINSTANCE hLibSecure32 = NULL;
PSecurityFunctionTable ntlmFuncs;
DWORD ntlmMaxMsg = 0;
PBYTE ntlmIBuf = NULL;
PBYTE ntlmOBuf = NULL;
CredHandle ntlmCrd;
BOOL ntlmHaveCrdHnd;
BOOL ntlmHaveCtxHnd;
struct _SecHandle ntlmSecHnd;
#define SEC_SUCCESS(Status) ((Status) >= 0)
#endif

/* �A�C�R���p�O���ϐ� */
#ifdef SUPPORT_ICON
HINSTANCE hLibKernel32 = NULL;
#endif

/******************************************************************************
* Prototypes
******************************************************************************/
/* �ȉ��\�P�b�g�p���b�p�֐� */
#ifdef DEBUG_SCK
int t_select(int, fd_set FAR *, fd_set FAR *, fd_set FAR *,
	const struct timeval FAR *);
int t_send(SOCKET, char FAR *, int, int);
int t_recv(SOCKET, char FAR *, int, int);
#else
#define t_select select
#define t_recv recv
#define t_send send
#endif

BOOL CtrlHandle(DWORD);
SOCKET GetListenSocket(USHORT);	/* �ҋ@�\�P�b�g�쐬 */
DWORD WINAPI LstnThread(void *);	/* �ҋ@�X���b�h */
DWORD WINAPI SendThread(void *);	/* ���M�X���b�h */
DWORD WINAPI RecvThread(void *);	/* ��M�X���b�h */
#ifdef SUPPORT_NTLM
BOOL AuthNTLM(LPTELNET_STRUCT);	/* NTLM�F�� */
#endif
void Usage(HANDLE, LPTELNET_STRUCT, BOOL);	/* �g�p���@ */

/******************************************************************************
* Function CtrlHandle
******************************************************************************/
BOOL
CtrlHandle(DWORD dwCtrlType)
{
	switch (dwCtrlType)
	{
	case CTRL_CLOSE_EVENT:
	case CTRL_LOGOFF_EVENT:
	case CTRL_SHUTDOWN_EVENT:
		break;
	default:
		break;
	}
	return TRUE;
}

/******************************************************************************
* Function t_select
******************************************************************************/
#ifdef DEBUG_SCK
int
t_select(int nfds, fd_set FAR * readfds, fd_set FAR * writefds,
	fd_set FAR * exceptfds, const struct timeval FAR * timeout)
{
	static BOOL tick = FALSE;
#ifdef SUPPORT_RBUF
	tick = tick ? FALSE : TRUE;
	return tick ? 1 : 0;
#else
	return select(nfds, readfds, writefds, exceptfds, timeout);
#endif
}
#endif

/******************************************************************************
* Function t_send
******************************************************************************/
#ifdef DEBUG_SCK
int
t_send(SOCKET s, char FAR * buf, int len, int flags)
{
	int ret;
	ret = send(s, buf, len, flags);
#ifdef DEBUG_SND
	{
		FILE *pFile;
		pFile = fopen("send.log", "ab");
		if (buf[0] == 0x1b)
			fwrite("\n", 1, 1, pFile);
		fwrite(buf, len, 1, pFile);
		fclose(pFile);
	}
#endif
	return ret;
}
#endif

/******************************************************************************
* Function t_recv
******************************************************************************/
#ifdef DEBUG_SCK
int
t_recv(SOCKET s, char FAR * buf, int len, int flags)
{
	int ret;
#ifdef SUPPORT_RBUF
	static char rbuf[RECV_BUFSIZ];
	static int nbuf = 0;
	static int ibuf = 0;
	if (nbuf > 0 && nbuf < len)
	{
		memcpy(buf, rbuf + ibuf, nbuf);
		len -= nbuf;
		ret = recv(s, buf + nbuf, len, flags);
		if (ret <= 0)
			return ret;
		ret = recv(s, rbuf, sizeof(rbuf), flags);
		if (ret <= 0)
			return ret;
		ibuf = 0;
		nbuf = ret;
	}
	else if (nbuf == 0)
	{
		ret = recv(s, rbuf, sizeof(rbuf), flags);
		if (ret <= 0)
			return ret;
		ibuf = 0;
		nbuf = ret;
	}
	else
		ret = len;
	memcpy(buf, rbuf + ibuf, len);
	nbuf -= len;
	ibuf += len;
#else
	ret = recv(s, buf, len, flags);
#endif
#ifdef DEBUG_RCV
	{
		FILE *pFile;
		pFile = fopen("recv.log", "ab");
		if (buf[0] == 0x1b)
			fwrite("\n", 1, 1, pFile);
		fwrite(buf, len, 1, pFile);
		fclose(pFile);
	}
#endif
	return ret;
}
#endif

/******************************************************************************
* Function AuthNTLM
******************************************************************************/
#ifdef SUPPORT_NTLM
BOOL
AuthNTLM(LPTELNET_STRUCT lpts)
{
	LONG ret;					/* �߂�l */
	U_CHAR c1, c2;				/* ��M���� */
	BOOL enable = FALSE;		/* �\�� */
	PSecurityFunctionTable(*pInit) (void);
	SECURITY_STATUS sStat;
	PSecPkgInfo pkgInfo;
	SecBufferDesc OBuffDesc;
	SecBufferDesc IBuffDesc;
	SecBuffer OSecBuff;
	SecBuffer ISecBuff;
	TimeStamp Lifetime;
	ULONG CtxAttr;
	INT Serial = 0;
	DWORD cbONum;
	DWORD cbINum;
	unsigned int cnt;
	unsigned char *data;

	if (lpts == NULL)
	{
		if (ntlmIBuf)
			free(ntlmIBuf);
		ntlmIBuf = NULL;
		if (ntlmOBuf)
			free(ntlmOBuf);
		ntlmOBuf = NULL;
		if (hLibSecure32)
			FreeLibrary(hLibSecure32);
		hLibSecure32 = NULL;
		return TRUE;
	}

	ret = t_recv(lpts->sock, &c1, 1, 0);
	if (ret <= 0)
		return FALSE;
	switch (c1)
	{
	case 1:
		do
		{
			ret = t_recv(lpts->sock, &c1, 1, 0);
			if (ret <= 0)
				break;
			ret = t_recv(lpts->sock, &c2, 1, 0);
			if (ret <= 0)
				break;
			if (c1 == 0x0F && c2 == 0x00)
				enable = TRUE;
		}
		while (c1 != 0xFF || c2 != 0xF0);

		if (!enable)
		{
			t_send(lpts->sock, "\xff\xfa\x25\x00\x00\x00\xff\xf0", 8, 0);
			break;
		}
		if ((GetVersion() & 0x80000000) == 0)
			hLibSecure32 = LoadLibrary("security.dll");
		else
			hLibSecure32 = LoadLibrary("secur32.dll");
		if (hLibSecure32 == NULL)
			return FALSE;
		pInit =
			(PSecurityFunctionTable(*)(void))GetProcAddress(hLibSecure32,
			SECURITY_ENTRYPOINT);
		if (pInit == NULL)
			return FALSE;
		ntlmFuncs = (PSecurityFunctionTable) pInit();
		if (ntlmFuncs == NULL)
			return FALSE;
		sStat = ntlmFuncs->QuerySecurityPackageInfo("NTLM", &pkgInfo);
		if (!SEC_SUCCESS(sStat))
			return FALSE;
		ntlmMaxMsg = pkgInfo->cbMaxToken;
		ntlmFuncs->FreeContextBuffer(pkgInfo);
		ntlmIBuf = (PBYTE) malloc(ntlmMaxMsg);
		ntlmOBuf = (PBYTE) malloc(ntlmMaxMsg);
		if (ntlmIBuf == NULL || ntlmOBuf == NULL)
			return FALSE;
		ntlmHaveCrdHnd = FALSE;
		ntlmHaveCtxHnd = FALSE;
		sStat = ntlmFuncs->AcquireCredentialsHandle(NULL,
			"NTLM",
			SECPKG_CRED_OUTBOUND,
			NULL, NULL, NULL, NULL, &ntlmCrd, &Lifetime);
		if (!SEC_SUCCESS(sStat))
			return FALSE;
		OBuffDesc.ulVersion = 0;
		OBuffDesc.cBuffers = 1;
		OBuffDesc.pBuffers = &OSecBuff;
		OSecBuff.cbBuffer = ntlmMaxMsg;
		OSecBuff.BufferType = SECBUFFER_TOKEN;
		OSecBuff.pvBuffer = ntlmOBuf;
		IBuffDesc.ulVersion = 0;
		IBuffDesc.cBuffers = 1;
		IBuffDesc.pBuffers = &ISecBuff;
		ISecBuff.cbBuffer = ntlmMaxMsg;
		ISecBuff.BufferType = SECBUFFER_TOKEN;
		ISecBuff.pvBuffer = ntlmIBuf;
		sStat = ntlmFuncs->InitializeSecurityContext(&ntlmCrd,
			NULL,
			NULL,
			0,
			0,
			SECURITY_NATIVE_DREP,
			NULL, 0, &ntlmSecHnd, &OBuffDesc, &CtxAttr, &Lifetime);
		if (!SEC_SUCCESS(sStat))
			return FALSE;
		ntlmHaveCtxHnd = TRUE;
		if ((SEC_I_COMPLETE_NEEDED == sStat) ||
			(SEC_I_COMPLETE_AND_CONTINUE == sStat))
		{
			if (ntlmFuncs->CompleteAuthToken)
			{
				sStat = ntlmFuncs->CompleteAuthToken(&ntlmCrd, &OBuffDesc);
				if (!SEC_SUCCESS(sStat))
					return FALSE;
			}
		}
		cbONum = OSecBuff.cbBuffer;
#ifdef DEBUG_NTA
		for (cnt = 0; cnt < (signed)cbONum; cnt++)
		{
			if ((cnt & 0xf) == 0)
				printf("%08X  ", cnt);
			printf("%02X", ntlmOBuf[cnt]);
			switch (cnt & 0xf)
			{
			case 7:
				printf("-");
				break;
			case 15:
				printf("\n");
				break;
			default:
				printf(",");
				break;
			}
		}
		if ((cbONum & 0xf) != 0)
			printf("\n");
#endif
		t_send(lpts->sock, "\xff\xfa\x25\x00\x0f\x00\x00", 7, 0);
		data = (char *)&cbONum;
		for (cnt = 0; cnt < 4; cnt++)
		{
			if (data[cnt] == 0xFF)
				t_send(lpts->sock, "\xFF\xFF", 2, 0);
			else
				t_send(lpts->sock, data + cnt, 1, 0);
		}
		t_send(lpts->sock, "\x02\x00\x00\x00", 4, 0);
		data = (char *)ntlmOBuf;
		for (cnt = 0; cnt < cbONum; cnt++)
		{
			if (data[cnt] == 0xff)
				t_send(lpts->sock, "\xff\xff", 2, 0);
			else
				t_send(lpts->sock, data + cnt, 1, 0);
		}
		t_send(lpts->sock, "\xff\xf0", 2, 0);
		return TRUE;
	case 2:
		ret = t_recv(lpts->sock, &c1, 1, 0);
		if (ret <= 0)
			break;
		ret = t_recv(lpts->sock, &c2, 1, 0);
		if (ret <= 0)
			break;
		if (c1 != 0x0F || c2 != 0x00)
			return FALSE;
		ret = t_recv(lpts->sock, (char *)&Serial, 1, 0);
		if (ret <= 0)
			break;
		if (Serial != 3 && Serial != 4)
		{
			DWORD dwEnd;
			INT cnt;
			for (cnt = 0; cnt < 4; cnt++)
			{
				ret = t_recv(lpts->sock, (char *)&cbINum + cnt, 1, 0);
				if (*(&cbINum + cnt) == 0xFF)
					ret = t_recv(lpts->sock, &c2, 1, 0);
				if (ret <= 0)
					break;
			}
			for (cnt = 0; cnt < 4; cnt++)
			{
				ret = t_recv(lpts->sock, (char *)&dwEnd + cnt, 1, 0);
				if (*(&dwEnd + cnt) == 0xFF)
					ret = t_recv(lpts->sock, &c2, 1, 0);
				if (ret <= 0)
					break;
			}
			if (dwEnd != 2)
				return FALSE;
			for (cnt = 0; cnt < (signed)cbINum; cnt++)
			{
				ret = t_recv(lpts->sock, ntlmIBuf + cnt, 1, 0);
				if (*(ntlmIBuf + cnt) == 0xFF)
					ret = t_recv(lpts->sock, &c2, 1, 0);
				if (ret <= 0)
					break;
			}
		}
		ret = t_recv(lpts->sock, &c1, 1, 0);
		if (ret <= 0)
			break;
		ret = t_recv(lpts->sock, &c2, 1, 0);
		if (ret <= 0)
			break;
		if (c1 == 0x0F && c2 == 0x00)
			return FALSE;
		if (Serial != 3 && Serial != 4)
		{
			cbONum = ntlmMaxMsg;
			OBuffDesc.ulVersion = 0;
			OBuffDesc.cBuffers = 1;
			OBuffDesc.pBuffers = &OSecBuff;
			OSecBuff.cbBuffer = ntlmMaxMsg;
			OSecBuff.BufferType = SECBUFFER_TOKEN;
			OSecBuff.pvBuffer = ntlmOBuf;
			IBuffDesc.ulVersion = 0;
			IBuffDesc.cBuffers = 1;
			IBuffDesc.pBuffers = &ISecBuff;
			ISecBuff.cbBuffer = cbINum;
			ISecBuff.BufferType = SECBUFFER_TOKEN;
			ISecBuff.pvBuffer = ntlmIBuf;
			sStat = ntlmFuncs->InitializeSecurityContext(&ntlmCrd,
				&ntlmSecHnd,
				NULL,
				0,
				0,
				SECURITY_NATIVE_DREP,
				&IBuffDesc, 0, &ntlmSecHnd, &OBuffDesc, &CtxAttr, &Lifetime);
			if (!SEC_SUCCESS(sStat))
				return FALSE;
			ntlmHaveCtxHnd = TRUE;
			if ((SEC_I_COMPLETE_NEEDED == sStat) ||
				(SEC_I_COMPLETE_AND_CONTINUE == sStat))
			{
				if (ntlmFuncs->CompleteAuthToken)
				{
					sStat =
						ntlmFuncs->CompleteAuthToken(&ntlmCrd, &OBuffDesc);
					if (!SEC_SUCCESS(sStat))
						return FALSE;
				}
			}
			cbONum = OSecBuff.cbBuffer;
			t_send(lpts->sock, "\xff\xfa\x25\x00\x0f\x00\x02", 7, 0);
			data = (char *)&cbONum;
			for (cnt = 0; cnt < 4; cnt++)
			{
				if (data[cnt] == 0xFF)
					t_send(lpts->sock, "\xFF\xFF", 2, 0);
				else
					t_send(lpts->sock, data + cnt, 1, 0);
			}
			t_send(lpts->sock, "\x02\x00\x00\x00", 4, 0);
			data = (char *)ntlmOBuf;
			for (cnt = 0; cnt < cbONum; cnt++)
			{
				if (data[cnt] == 0xff)
					t_send(lpts->sock, "\xff\xff", 2, 0);
				else
					t_send(lpts->sock, data + cnt, 1, 0);
			}
			t_send(lpts->sock, "\xff\xf0", 2, 0);

			return TRUE;
		}
		else if (Serial == 3)
		{
			return TRUE;
		}
	}
	return FALSE;
}
#endif

/******************************************************************************
* Function GetListenSocket
******************************************************************************/
SOCKET
GetListenSocket(USHORT port)
{
	SOCKET sock_lstn;			/* �ҋ@�\�P�b�g */
	SOCKADDR_IN addr_lstn;		/* �ҋ@�A�h���X */

	sock_lstn = socket(AF_INET, SOCK_STREAM, PF_UNSPEC);
	if (sock_lstn == INVALID_SOCKET)
		return INVALID_SOCKET;
	addr_lstn.sin_addr.s_addr = 0;
	if (port)
		addr_lstn.sin_port = htons(port);
	else
		addr_lstn.sin_port = htons(0);
	addr_lstn.sin_family = AF_INET;
	if (bind(sock_lstn, (LPSOCKADDR) & addr_lstn, sizeof(addr_lstn)) ==
		SOCKET_ERROR)
	{
		shutdown(sock_lstn, SD_BOTH);
		closesocket(sock_lstn);
		return INVALID_SOCKET;
	}
	if (listen(sock_lstn, 1) != 0)
	{
		shutdown(sock_lstn, SD_BOTH);
		closesocket(sock_lstn);
		return INVALID_SOCKET;
	}
	return sock_lstn;
}

/******************************************************************************
* Function LstnThread
******************************************************************************/
DWORD WINAPI
LstnThread(void *param)
{
	LPTELNET_STRUCT lpts;		/* �ʐM�p�����\���� */
	TELNET_STRUCT new_ts;		/* �ʐM�p�����\���� */
	U_CHAR temp[256];			/* �ėp������       */
	LPSTR alist;				/* �A�h���X���X�g   */
	LPSTR plist;				/* �|�[�g���X�g     */
	SOCKET sock_lstn;			/* �ҋ@�\�P�b�g     */
	SOCKET sock_data;			/* �f�[�^�\�P�b�g   */
	SOCKADDR_IN addr_lstn;		/* �ҋ@�A�h���X     */
	SOCKADDR_IN addr_temp;		/* �����p�A�h���X   */
	LONG ret;					/* API�ߒl          */
	fd_set fdsetr, fdsetw, fdsete;	/* �\�P�b�g���     */
	TIMEVAL timeout = { 0, 10000 };	/* �^�C���A�E�g     */

	/* �ʐM�p�����\���̂��擾 */
	lpts = (LPTELNET_STRUCT) param;
	if (lpts == NULL)
		return 0;

	memcpy(&new_ts, lpts, sizeof(TELNET_STRUCT));

	/* �T�[�o�|�[�g������Ȃ�ΐV�����ҋ@�\�P�b�g���������� */

	/* �Ȃ���΂���̑ҋ@�\�P�b�g���������� */
	if (new_ts.serv_port)
	{
		sock_lstn = GetListenSocket(new_ts.serv_port);
		new_ts.sock = sock_lstn;
	}
	else
		sock_lstn = GetListenSocket(0);

	if (sock_lstn == INVALID_SOCKET)
	{
		strcpy(temp, "�ҋ@�\�P�b�g���쐬�ł��܂���\n");
		WriteFile(lpts->stdo, temp, strlen(temp), &ret, NULL);
		return 0;
	}

	/* �ҋ@�\�P�b�g�������̃A�h���X���擾���� */
	ret = sizeof(SOCKADDR);
	if (getsockname(sock_lstn, (LPSOCKADDR) & addr_lstn, (int *)&ret)
		== SOCKET_ERROR)
	{
		shutdown(sock_lstn, SD_BOTH);
		closesocket(sock_lstn);
		strcpy(temp, "�ҋ@�\�P�b�g�������ł��܂���\n");
		WriteFile(lpts->stdo, temp, strlen(temp), &ret, NULL);
		return 0;
	}

	/* �T�[�o�|�[�g������Ȃ�΃A�h���X�����[�J���z�X�g�ɐݒ肷�� */

	/* �Ȃ���Ό��ݎg�p���̑Θb�\�P�b�g�̃A�h���X���擾���� */
	if (new_ts.serv_port)
	{
		char hostname[256];
		LPHOSTENT host;
		gethostname(hostname, sizeof(hostname));
		host = gethostbyname(hostname);
		memmove((char *)&addr_temp.sin_addr, host->h_addr, host->h_length);
	}
	else
	{
		ret = sizeof(SOCKADDR);
		if (getsockname(new_ts.sock, (LPSOCKADDR) & addr_temp, (int *)&ret)
			== SOCKET_ERROR)
		{
			shutdown(sock_lstn, SD_BOTH);
			closesocket(sock_lstn);
			strcpy(temp, "�ҋ@�\�P�b�g�������ł��܂���\n");
			WriteFile(lpts->stdo, temp, strlen(temp), &ret, NULL);
			return 0;
		}
	}

	/* �A�h���X�ƃ|�[�g�ԍ���\������ */
	alist = (char *)&addr_temp.sin_addr;
	plist = (char *)&addr_lstn.sin_port;
	wsprintf(temp, "PORT %d,%d,%d,%d,%d,%d\n",
		UC(alist[0]), UC(alist[1]), UC(alist[2]), UC(alist[3]),
		UC(plist[0]), UC(plist[1]));
	WriteFile(new_ts.stdo, temp, strlen(temp), (DWORD *) & ret, NULL);
	if (!new_ts.serv_port)
	{
		wsprintf(temp, "PORT %d,%d,%d,%d,%d,%d\r\n",
			UC(alist[0]), UC(alist[1]), UC(alist[2]), UC(alist[3]),
			UC(plist[0]), UC(plist[1]));
		t_send(new_ts.sock, temp, strlen(temp), 0);
	}

	/* �N���C�A���g����̐ڑ���҂� */
	FD_ZERO(&fdsetw);
	FD_ZERO(&fdsete);
	for (;;)
	{
		FD_ZERO(&fdsetr);
		FD_SET(sock_lstn, &fdsetr);
		ret = select(0, &fdsetr, &fdsetw, &fdsete, &timeout);
		if (ret == 0)
			break;
		if (lpts->sock == INVALID_SOCKET)
		{
			ret = -1;
			break;
		}
	}
	Sleep(200);

	/* �N���C�A���g����̐ڑ���҂� */
	FD_ZERO(&fdsetw);
	FD_ZERO(&fdsete);
	for (;;)
	{
		FD_ZERO(&fdsetr);
		FD_SET(sock_lstn, &fdsetr);
		ret = select(0, &fdsetr, &fdsetw, &fdsete, &timeout);
		if (ret != 0)
			break;
		if (lpts->sock == INVALID_SOCKET)
		{
			ret = -1;
			break;
		}
	}

	new_ts.lock = FALSE;
	lpts->lock = TRUE;

	if (ret > 0)
	{
		ret = sizeof(SOCKADDR);
		sock_data = accept(sock_lstn, (LPSOCKADDR) & addr_lstn, (int *)&ret);

		/* �T�[�o�|�[�g������Ȃ�΃N���C�A���g�\�P�b�g�ƑΘb������ */
		new_ts.sock = sock_data;
		if (new_ts.serv_port)
			lpts->sock = sock_data;

		/* ��̏����͎�M�X���b�h�ɔC���� */
		RecvThread(&new_ts);
	}
	lpts->lock = FALSE;
	closesocket(sock_lstn);
	return 0;
}

/******************************************************************************
* Function SendThread
******************************************************************************/
DWORD WINAPI
SendThread(void *param)
{
	LPTELNET_STRUCT lpts;		/* �ʐM�p�����\���� */
	LONG ret;					/* �߂�l           */
	SOCKET sock;				/* �\�P�b�g         */
	INPUT_RECORD ir;			/* ���̓��R�[�h     */
#ifdef SUPPORT_JPNK
	INT lstmode = KANJI_NONE;	/* �O��̊������   */
	U_CHAR c[2];				/* �����R�[�h       */
	U_CHAR lstbyte = 0;			/* �O��̃o�C�g     */
#endif
	U_CHAR curbyte = 0;			/* ���݂̃o�C�g     */
	U_CHAR sbuf[16];			/* ����M��         */
	WORD vkey;					/* ���z�L�[�R�[�h   */
	DWORD ctrl;					/* �R���g���[���L�[ */
	BOOL loop = TRUE;			/* ���[�v�t���O     */
	CONSOLE_SCREEN_BUFFER_INFO csbi_now;	/* �[�����         */
#ifdef SUPPORT_NAWS
	INT w, h;					/* �[���c��         */
	SMALL_RECT old_rct = {		/* �ėp�͈͕ϐ�     */
		-1, -1, -1, -1
	};
#endif
#ifdef SUPPORT_GPMP
	DWORD lstbutton = -1;		/* �O��̃{�^��     */
	COORD lstcoord = {			/* �O��̈ʒu       */
		-1, -1
	};
#endif
	HANDLE hThread = NULL;		/* �X���b�h�n���h�� */
	DWORD ThreadID = 0;			/* �X���b�h�h�c     */
	HANDLE hlpo;				/* �w���v���       */
	COORD coord;				/* �ėp�ʒu�ϐ�     */
	DWORD dwWritten;

	/* �ʐM�p�����\���̂��擾 */
	lpts = (LPTELNET_STRUCT) param;
	if (lpts == NULL)
		ExitThread(0);

	if (lpts->serv_port == 23)
	{
		sbuf[0] = 0xFF;
		sbuf[1] = 0xFB;
		sbuf[2] = 0x1F;
		t_send(lpts->sock, (CHAR *) sbuf, 3, 0);
		//sbuf[0] = 0xFF;
		//sbuf[1] = 0xFE;
		//sbuf[2] = 0x03;
		//t_send(lpts->sock, (CHAR *) sbuf, 3, 0);
	}

	/* ���M���[�v */
	while (loop)
	{
#ifdef SUPPORT_PIPE
		if (GetFileType(lpts->stdi) == FILE_TYPE_PIPE)
		{
			if (WaitForSingleObject(lpts->stdi, INFINITE) != WAIT_OBJECT_0)
				continue;
			if (!ReadFile(lpts->stdi, &curbyte, 1, (DWORD *) & ret, NULL))
				loop = FALSE;
			else
				t_send(lpts->sock, &curbyte, 1, 0);
			continue;
		}
#endif

		/* ���͂��`�F�b�N���� */
		ReadConsoleInput(lpts->stdi, &ir, 1, (DWORD *) & ret);
		if (ret == 0)
			continue;
		switch (ir.EventType)
		{
#ifdef SUPPORT_GPMP
		case MOUSE_EVENT:
			if (!lpts->mouse)
				continue;
			if (lstbutton == ir.Event.MouseEvent.dwButtonState)
				continue;
			if (ir.Event.MouseEvent.dwEventFlags == MOUSE_MOVED)
				continue;
			GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
			lstbutton = ir.Event.MouseEvent.dwButtonState;
			lstcoord = ir.Event.MouseEvent.dwMousePosition;
			sprintf(sbuf, "\x1b[M%c%c%c",
				32 + ((lstbutton != 0) ? ((char)lstbutton - 1) : 3),
				32 + lstcoord.X - csbi_now.srWindow.Left + 1,
				32 + lstcoord.Y - csbi_now.srWindow.Top + 1);
			t_send(lpts->sock, sbuf, 6, 0);
			break;
#endif
#ifdef SUPPORT_NAWS
		case WINDOW_BUFFER_SIZE_EVENT:
			if (!lpts->naws == NAWS_ON)
				break;
#ifdef SUPPORT_PIPE
			if (GetFileType(lpts->stdo) == FILE_TYPE_PIPE)
				break;
#endif
			GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
			RESTORE_IME(lpts, csbi_now);
			if (memcmp(&csbi_now.srWindow, &old_rct, sizeof(SMALL_RECT)))
			{
				w = csbi_now.srWindow.Right - csbi_now.srWindow.Left + 1;
				h = csbi_now.srWindow.Bottom - csbi_now.srWindow.Top + 1;
				sbuf[0] = 0xFF;
				sbuf[1] = 0xFA;
				sbuf[2] = 0x1F;
				sbuf[3] = HIBYTE(w);
				sbuf[4] = LOBYTE(w);
				sbuf[5] = HIBYTE(h);
				sbuf[6] = LOBYTE(h);
				sbuf[7] = 0xFF;
				sbuf[8] = 0xF0;
				t_send(lpts->sock, sbuf, 9, 0);
			}
			old_rct = csbi_now.srWindow;
			break;
#endif
		case KEY_EVENT:
			/* IME�ւ̓��͂͗����Ȃ� */
			if ((ir.Event.KeyEvent.uChar.UnicodeChar == 0
					&& ir.Event.KeyEvent.wVirtualKeyCode == 13)
				|| !ir.Event.KeyEvent.bKeyDown)
				continue;
			vkey = ir.Event.KeyEvent.wVirtualKeyCode;
			ctrl = ir.Event.KeyEvent.dwControlKeyState;

			switch (vkey)
			{
			case VK_SHIFT:
			case VK_CONTROL:
			case VK_MENU:
				continue;
			}
			if (vkey >= 112
				&& (ctrl & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED)))
			{
				switch (vkey)
				{
				case 0x70:
					/* CTRL-F1 �Ńw���v */
					GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
					hlpo =
						CreateConsoleScreenBuffer(GENERIC_READ |
						GENERIC_WRITE, 0, NULL, CONSOLE_TEXTMODE_BUFFER,
						NULL);
					coord.X = 0;
					coord.Y = 0;
					FillConsoleOutputAttribute(hlpo,
						BACKGROUND_WHITE | BACKGROUND_INTENSITY,
						csbi_now.dwSize.X * csbi_now.dwSize.Y,
						coord, &dwWritten);
					SetConsoleTextAttribute(hlpo,
						BACKGROUND_WHITE | BACKGROUND_INTENSITY);
					Usage(hlpo, lpts, FALSE);
					SetConsoleActiveScreenBuffer(hlpo);
					ret = 1;
					while (loop)
					{
						ReadConsoleInput(lpts->stdi, &ir, 1, (DWORD *) & ret);
						if ((ir.Event.KeyEvent.uChar.UnicodeChar == 0
								&& ir.Event.KeyEvent.wVirtualKeyCode == 13)
							|| !ir.Event.KeyEvent.bKeyDown)
							continue;
						if (ir.EventType == KEY_EVENT)
							break;
					}
					SetConsoleActiveScreenBuffer(lpts->stdo);
					CloseHandle(hlpo);
					break;
				case 0x72:
					/* CTRL-F3 �Ŏ�M�\�P�b�g���J�� */
					if (hThread == NULL)
					{
						lpts->serv_port = 0;
						hThread = CreateThread(NULL,
							0, LstnThread, (void *)lpts, 0, &ThreadID);
					}
					else
					{
						if (WaitForSingleObject(hThread, 0) == WAIT_TIMEOUT)
							TerminateThread(hThread, 0);
						CloseHandle(hThread);
						hThread = NULL;
					}
					break;
				case 0x73:
					/* CTRL-F4 �ŏI������ */
					if (ir.Event.KeyEvent.dwControlKeyState
						& (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED))
						loop = FALSE;
					break;
#ifdef SUPPORT_JPNK
				case 0x74:
					/* CTRL-F5 �Ŋ������[�h�ؑ� */
					switch (lpts->kanji)
					{
					case KANJI_SJIS:
						lpts->kanji = KANJI_JIS7;
						break;
					case KANJI_JIS7:
						lpts->kanji = KANJI_EUCJ;
						break;
					case KANJI_EUCJ:
						lpts->kanji = KANJI_NONE;
						break;
					default:
						lpts->kanji = KANJI_SJIS;
						break;
					}
					lstbyte = 0;
					lstmode = KANJI_NONE;
					break;
#endif
				case 0x75:
					/* CTRL-F6 �Ń��[�J���G�R�[ */
					lpts->echo = lpts->echo ? FALSE : TRUE;
					break;
				case 0x76:
					/* CTRL-F7 ��CRLF�𑗐M */
					switch (lpts->line & ~LINE_AUTO)
					{
					case LINE_NONE:
						lpts->line = LINE_CR;
						break;
					case LINE_CR:
						lpts->line = LINE_LF;
						break;
					case LINE_LF:
						lpts->line = LINE_CRLF;
						break;
					case LINE_CRLF:
						lpts->line = LINE_AUTO;
						break;
					}
					break;
#ifdef SUPPORT_NAWS
				case 0x77:
					/* CTRL-F8 ��NAWS��ON/OFF */
					lpts->naws = lpts->naws ? NAWS_OFF : NAWS_ON;
					break;
#endif
				case 0x78:
					/* CTRL-F9 �Ńx����ON/OFF */
					lpts->bell = lpts->bell ? FALSE : TRUE;
					break;
				case 0x79:
					/* CTRL-F10 ��vt100��ؑ� */
					lpts->vt100 = lpts->vt100 ? FALSE : TRUE;
					break;
				}
				continue;
			}
			for (ret = 0; ks[ret].key != 0; ret++)
				if (ks[ret].key == vkey)
					break;
			if (ks[ret].key != 0)
			{
				if (ctrl & SHIFT_PRESSED)
					t_send(lpts->sock, "~", 1, 0);
				if (!lpts->vt100)
					strcpy(sbuf, ks[ret].esc1);
				else
					strcpy(sbuf, ks[ret].esc2);
				if (lpts->cursor && (vkey == VK_UP || vkey == VK_DOWN
						|| vkey == VK_LEFT || vkey == VK_RIGHT))
					sbuf[1] = 'O';
				t_send(lpts->sock, sbuf, strlen(sbuf), 0);
				break;
			}
			if (ctrl & (LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED))
			{
				curbyte = (U_CHAR) ir.Event.KeyEvent.uChar.AsciiChar;
				sbuf[0] = 0x1B;
				sbuf[1] = curbyte;
				t_send(lpts->sock, sbuf, 2, 0);
#ifdef SUPPORT_JPNK
				lstbyte = curbyte;
#endif
			}
			else
			{
				curbyte = (U_CHAR) ir.Event.KeyEvent.uChar.AsciiChar;

				if (curbyte == '\r' || curbyte == '\n')
				{
					/* Cr �Ȃ�� CrLf �𑗐M���� */
					switch (lpts->line & ~LINE_AUTO)
					{
					case LINE_NONE:
					case LINE_CRLF:
						t_send(lpts->sock, "\r\n", 2, 0);
						break;
					case LINE_LF:
						t_send(lpts->sock, "\n\0", 2, 0);
						break;
					case LINE_CR:
						t_send(lpts->sock, "\r\0", 2, 0);
						break;
					}
#ifdef SUPPORT_JPNK
					lstbyte = curbyte;
#endif
					if (lpts->echo)
						WriteFile(lpts->stdo, "\r\n", 1, (DWORD *) & ret,
							NULL);
					continue;
				}

				if (lpts->echo)
					WriteFile(lpts->stdo, &curbyte, 1, (DWORD *) & ret, NULL);

#ifdef SUPPORT_JPNK
				if (lstmode == KANJI_NONE && curbyte >= 0xA0
					&& curbyte <= 0xDF)
				{
					switch (lpts->kanji)
					{
					case KANJI_NONE:
						sprintf(sbuf, "\\x%02x", curbyte);
						t_send(lpts->sock, sbuf, strlen(sbuf), 0);
						lstmode = KANJI_NONE;
						break;
					case KANJI_JIS7:
						if (lstmode != KANJI_KANA)
						{
							sbuf[0] = '\x1b';
							sbuf[1] = '(';
							sbuf[2] = 'I';
							t_send(lpts->sock, sbuf, 3, 0);
							lstmode = KANJI_KANA;
						}
						t_send(lpts->sock, &curbyte, 1, 0);
						break;
					case KANJI_EUCJ:
						sbuf[0] = 0x8E;
						t_send(lpts->sock, sbuf, 1, 0);
						t_send(lpts->sock, &curbyte, 1, 0);
						lstmode = KANJI_NONE;
						break;
					}
				}
				else if (lstmode == KANJI_NONE && curbyte & 0x80)
					lstmode = KANJI_START;
				else if (lstmode == KANJI_START && lstbyte & 0x80)
				{
					c[0] = lstbyte;
					c[1] = curbyte;
					switch (lpts->kanji)
					{
					case KANJI_NONE:
						sprintf(sbuf, "\\x%02x\\x%02x", lstbyte, curbyte);
						t_send(lpts->sock, sbuf, strlen(sbuf), 0);
						lstmode = KANJI_NONE;
						break;
					case KANJI_JIS7:
						if (lstmode != KANJI_START)
						{
							sbuf[0] = '\x1b';
							sbuf[1] = '(';
							sbuf[2] = 'B';
							t_send(lpts->sock, sbuf, 3, 0);
						}
						c[0] -= (c[0] <= 0x9f) ? 0x71 : 0xb1;
						c[0] = (c[0] << 1) + 1;
						if (c[1] >= 0x9e)
						{
							c[1] -= 0x7d;
							c[0]++;
						}
						else
							c[1] -= 0x1f;
						t_send(lpts->sock, c, 2, 0);
						break;
					case KANJI_SJIS:
						t_send(lpts->sock, c, 2, 0);
						lstmode = KANJI_NONE;
						break;
					case KANJI_EUCJ:
						c[0] -= (c[0] <= 0x9f) ? 0x71 : 0xb1;
						c[0] = (c[0] << 1) + 1;
						if (c[1] >= 0x9e)
						{
							c[1] -= 0x7e;
							c[0]++;
						}
						else if (c[1] > 0x7f)
							c[1] -= 0x20;
						else
							c[1] -= 0x1f;
						c[0] |= 0x80;
						c[1] |= 0x80;
						t_send(lpts->sock, c, 2, 0);
						lstmode = KANJI_NONE;
						break;
					}
				}
#endif
				else
				{
#ifdef SUPPORT_JPNK
					if (lpts->kanji == KANJI_JIS7 && lstmode != KANJI_NONE)
					{
						sbuf[0] = '\x1b';
						sbuf[1] = '(';
						sbuf[2] = 'J';
						t_send(lpts->sock, sbuf, 3, 0);
					}
					lstmode = KANJI_NONE;
#endif
					/* ����ȊO�Ȃ�΂��̂܂� ASCII �𑗐M���� */
					t_send(lpts->sock, &curbyte, 1, 0);
				}
				if (ret == SOCKET_ERROR)
				{
					shutdown(lpts->sock, SD_BOTH);
					loop = FALSE;
				}
#ifdef SUPPORT_JPNK
				lstbyte = curbyte;
#endif
			}
			break;
		}
	}

	if (hThread)
	{
		if (WaitForSingleObject(hThread, 0) == WAIT_TIMEOUT)
			TerminateThread(hThread, 0);
		CloseHandle(hThread);
	}
	sock = lpts->sock;
	lpts->sock = INVALID_SOCKET;
	closesocket(sock);
	lpts->lock = FALSE;
	return 0;
}

/******************************************************************************
* Function RecvThread
******************************************************************************/
DWORD WINAPI
RecvThread(void *param)
{
	LPTELNET_STRUCT lpts;		/* �ʐM�p�����\���� */
	LONG ret = 0;				/* API�ߒl          */
	U_CHAR c1, c2;				/* ��M����         */
#ifdef SUPPORT_JPNK
	BOOL dbcs = FALSE;			/* �������[�h       */
#endif
	LPSTR temp;					/* �G���[���b�Z�[�W */
	U_CHAR sbuf[16];			/* ����M��         */
	U_CHAR lc = ' ';			/* �O��̃L�����N�^ */
	CONSOLE_SCREEN_BUFFER_INFO csbi_now;	/* ���݂̒[�����   */
	CONSOLE_CURSOR_INFO cci_old, cci_new;	/* �J�[�\�����     */
	DWORD dwWritten, dwConSize;	/* �ėp�ϐ�         */
	COORD coord = {				/* �ėp�ʒu�ϐ�     */
		0, 0
	};
	INT w, h;					/* �[���c��         */
	SMALL_RECT scr_rct = {		/* �X�N���[���̈�   */
		-1, -1, -1, -1
	};
	SMALL_RECT mov_rct = {		/* �ړ��̈�         */
		-1, -1, -1, -1
	};
	CHAR_INFO ci;				/* �h�ׂ����       */
	WORD attr_old, attr_set, attr_new;	/* �[���F���       */
	fd_set fdsetr, fdsetw, fdsete;	/* �\�P�b�g���     */
	TIMEVAL timeout = { 0, 10000 };	/* �^�C���A�E�g     */
#ifdef SUPPORT_SWAP
	HANDLE hswap;				/* ���݉��         */
	CONSOLE_SCREEN_BUFFER_INFO csbi_swp;	/* ���݉�ʏ��     */
#endif
	SMALL_RECT old_rct = {		/* �ėp�͈͕ϐ�     */
		-1, -1, -1, -1
	};
#ifdef SUPPORT_SYMB
	INT haveSymbol = SYMBOL_NO;	/* �V���{���̗L��   */
#endif
	BOOL haveEscape = FALSE;	/* �G�X�P�[�v�̗L�� */

	lpts = (LPTELNET_STRUCT) param;
	if (lpts == NULL)
		return 0;

	GetConsoleCursorInfo(lpts->stdo, &cci_old);
	GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
	RESTORE_IME(lpts, csbi_now);
	attr_old = csbi_now.wAttributes;
	attr_new = attr_old;
	attr_set = attr_old;
	coord = csbi_now.dwCursorPosition;
#ifdef SUPPORT_SWAP
	hswap = lpts->stdo;
#endif

	if (coord.Y > csbi_now.srWindow.Bottom - 1)
	{
		mov_rct.Left = 0;
		mov_rct.Top = 0;
		mov_rct.Right = csbi_now.dwSize.X - 1;
		mov_rct.Bottom = csbi_now.dwSize.Y - 1;
		coord.X = 0;
		coord.Y = -1;
		ci.Char.AsciiChar = ' ';
		ci.Attributes = csbi_now.wAttributes;
		ScrollConsoleScreenBuffer(lpts->stdo, &mov_rct, &mov_rct, coord, &ci);
		coord.Y = csbi_now.dwCursorPosition.Y - 1;
		SetConsoleCursorPosition(lpts->stdo, coord);
	}

#ifdef SUPPORT_NAWS
	FD_ZERO(&fdsetw);
	FD_ZERO(&fdsete);
#endif

	/* ��M���[�v */
	for (;;)
	{
#ifdef SUPPORT_NAWS
		FD_ZERO(&fdsetr);
		FD_SET(lpts->sock, &fdsetr);
		if (t_select(0, &fdsetr, &fdsetw, &fdsete, &timeout) == 0)
		{
			if (lpts->naws == NAWS_ON)
			{
#ifdef SUPPORT_PIPE
				if (GetFileType(lpts->stdo) == FILE_TYPE_PIPE)
					continue;
#endif
				GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
				RESTORE_IME(lpts, csbi_now);
				if (memcmp(&csbi_now.srWindow, &old_rct, sizeof(SMALL_RECT)))
				{
					w = csbi_now.srWindow.Right - csbi_now.srWindow.Left + 1;
					h = csbi_now.srWindow.Bottom - csbi_now.srWindow.Top + 1;
					sbuf[0] = 0xFF;
					sbuf[1] = 0xFA;
					sbuf[2] = 0x1F;
					sbuf[3] = HIBYTE(w);
					sbuf[4] = LOBYTE(w);
					sbuf[5] = HIBYTE(h);
					sbuf[6] = LOBYTE(h);
					sbuf[7] = 0xFF;
					sbuf[8] = 0xF0;
					t_send(lpts->sock, sbuf, 9, 0);
				}
				old_rct = csbi_now.srWindow;
			}
			continue;
		}
#endif
		if (!haveEscape)
		{
			c1 = 0;
			ret = t_recv(lpts->sock, &c1, 1, 0);
			if (ret <= 0)
				break;
			while (lpts->lock)
				Sleep(200);
		}
		else
			haveEscape = FALSE;

		/* ����M���Ȃ�΂���ɑ΂��鉞�������� */
		if (c1 == 0xFF)
		{
			ret = t_recv(lpts->sock, &c1, 1, 0);
			if (ret <= 0)
				break;
#ifdef DEBUG_CTX
			printf("FF %02X ", c1);
#endif
			switch (c1)
			{
			case 0xFA:			/* SB */
				c1 = 0;
				ret = t_recv(lpts->sock, &c2, 1, 0);
				if (ret <= 0)
					break;
#ifdef DEBUG_CTX
				printf("%02X\n", c2);
#endif
				switch (c2)
				{
				case 0x22:
					sbuf[0] = 0xFF;
					sbuf[1] = 0xFE;
					sbuf[2] = c2;
					t_send(lpts->sock, sbuf, 3, 0);
					break;
#ifdef SUPPORT_NTLM
				case 0x25:
					if (lpts->ntlm)
					{
						AuthNTLM(lpts);
						break;
					}
#endif
				default:
					do
					{
						ret = t_recv(lpts->sock, &c2, 1, 0);
						if (ret <= 0)
							break;
						if (c2 == 0xFF && c1 == 0)
							c1 = 1;
						else if (c2 == 0xf0 && c1 == 1)
							c1 = 2;
						else
							c1 = 0;
					}
					while (c1 != 2);
				}
				break;
			case 0xFB:			/* WILL */
				ret = t_recv(lpts->sock, &c2, 1, 0);
				if (ret <= 0)
					break;
#ifdef DEBUG_CTX
				printf("%02X\n", c2);
#endif
				sbuf[0] = 0xFF;
				if (c2 == 0x05)
					sbuf[1] = 0xFE;
				else
					sbuf[1] = 0xFD;
				sbuf[2] = c2;
				t_send(lpts->sock, sbuf, 3, 0);
				break;
			case 0xFC:			/* WONT */
				sbuf[0] = 0xFF;
				sbuf[1] = 0xFE;
				sbuf[2] = c2;
				t_send(lpts->sock, sbuf, 3, 0);
				break;
			case 0xFD:			/* DO */
				ret = t_recv(lpts->sock, &c2, 1, 0);
				if (ret <= 0)
					break;
#ifdef DEBUG_CTX
				printf("%02X\n", c2);
#endif
				switch (c2)
				{
				case 0x03:
					sbuf[0] = 0xFF;
					sbuf[1] = 0xFB;
					sbuf[2] = 0x03;
					t_send(lpts->sock, sbuf, 3, 0);
					break;
				case 0x18:		/* TERMTYPE */
					sbuf[0] = 0xFF;
					sbuf[1] = 0xFB;
					sbuf[2] = 0x18;
					t_send(lpts->sock, sbuf, 3, 0);
					sbuf[0] = 0xFF;
					sbuf[1] = 0xFA;
					sbuf[2] = 0x18;
					sbuf[3] = 0x00;
					t_send(lpts->sock, sbuf, 4, 0);
					t_send(lpts->sock, lpts->term, strlen(lpts->term), 0);
					sbuf[0] = 0xFF;
					sbuf[1] = 0xF0;
					t_send(lpts->sock, sbuf, 2, 0);
					break;
				case 0x1F:		/* NAWS */
#ifdef SUPPORT_PIPE
					if (GetFileType(lpts->stdo) == FILE_TYPE_PIPE)
						break;
#endif
					GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
					RESTORE_IME(lpts, csbi_now);
					/* NAWS �Ŏg�p */
					if (memcmp(&csbi_now.srWindow, &old_rct,
							sizeof(SMALL_RECT)))
					{
						if (lpts->naws == NAWS_AUTO)
							lpts->naws = NAWS_ON;
						w = csbi_now.srWindow.Right
							- csbi_now.srWindow.Left + 1;
						h = csbi_now.srWindow.Bottom
							- csbi_now.srWindow.Top + 1;
						sbuf[0] = 0xFF;
						sbuf[1] = 0xFB;
						sbuf[2] = 0x1F;
						t_send(lpts->sock, sbuf, 3, 0);
						sbuf[0] = 0xFF;
						sbuf[1] = 0xFA;
						sbuf[2] = 0x1F;
						sbuf[3] = HIBYTE(w);
						sbuf[4] = LOBYTE(w);
						sbuf[5] = HIBYTE(h);
						sbuf[6] = LOBYTE(h);
						sbuf[7] = 0xFF;
						sbuf[8] = 0xF0;
						t_send(lpts->sock, sbuf, 9, 0);
					}
					old_rct = csbi_now.srWindow;
					break;
				case 0x25:		/* NTLM */
#ifdef SUPPORT_JPNK
					lpts->kanji = KANJI_SJIS;
#endif
					lpts->line = LINE_CRLF;
#ifdef SUPPORT_NTLM
					if (lpts->ntlm)
					{
						sbuf[0] = 0xFF;
						sbuf[1] = 0xFB;
						sbuf[2] = 0x25;
						t_send(lpts->sock, sbuf, 3, 0);
						break;
					}
#endif
				default:
					sbuf[0] = 0xFF;
					sbuf[1] = 0xFC;
					sbuf[2] = c2;
					t_send(lpts->sock, sbuf, 3, 0);
					break;
				}
				break;
			case 0xFE:			/* DONT */
				ret = t_recv(lpts->sock, &c1, 1, 0);
				if (ret <= 0)
					break;
				break;
			default:
				break;
			}
			continue;
		}

#ifdef SUPPORT_PIPE
		if (GetFileType(lpts->stdo) == FILE_TYPE_PIPE)
		{
			WriteFile(lpts->stdo, &c1, 1, (DWORD *) & ret, NULL);
			continue;
		}
		else
#endif
		if ((c1 == 0x0E))
		{
#ifdef SUPPORT_SYMB
			haveSymbol |= SYMBOL_SC;
#endif
			lpts->vt100 = TRUE;
			continue;
		}
		else if ((c1 == 0x0F))
		{
#ifdef SUPPORT_SYMB
			haveSymbol &= ~SYMBOL_SC;
#endif
			lpts->vt100 = FALSE;
			continue;
		}
		else if ((c1 == 0xF2))
			continue;
		else if ((c1 == 0x07))
		{
			if (lpts->bell)
				WriteFile(lpts->stdo, &c1, 1, (DWORD *) & ret, NULL);
			else
			{
				LPWORD oldattrs;
				WORD newattr;
				newattr = ~attr_new & 0xff;
				coord.X = 0;
				coord.Y = 0;
				GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
				oldattrs =
					(LPWORD) malloc(csbi_now.dwSize.X * csbi_now.dwSize.Y *
					sizeof(WORD));
				ReadConsoleOutputAttribute(lpts->stdo, oldattrs,
					csbi_now.dwSize.X * csbi_now.dwSize.Y, coord, &dwWritten);
				FillConsoleOutputAttribute(lpts->stdo, newattr,
					csbi_now.dwSize.X * csbi_now.dwSize.Y, coord, &dwWritten);
				Sleep(15);
				WriteConsoleOutputAttribute(lpts->stdo, oldattrs,
					csbi_now.dwSize.X * csbi_now.dwSize.Y, coord, &dwWritten);
				free(oldattrs);
			}
			continue;
		}
#ifdef SUPPORT_JPNK
		else if (lpts->kanji != KANJI_NONE && lpts->kanji != KANJI_JIS7
			&& c1 & 0x80 && haveSymbol == SYMBOL_NO)
			dbcs = TRUE;
#endif
#ifdef SUPPORT_SYMB
		else if (c1 != 0x1B && haveSymbol != SYMBOL_NO)
		{
			BOOL loop = TRUE;
			c2 = c1;
			for (;;)
			{
				switch (c2)
				{
				case 0x1b:
					loop = FALSE;
					haveEscape = TRUE;
					c1 = c2;
					break;
				case 0x30:
					haveSymbol |= SYMBOL_GL;
					break;
				case 0x42:
					haveSymbol &= ~SYMBOL_GL;
					loop = FALSE;
					break;
				case 0xD9:
				case 0x6a:
					c2 = 0x04;
					break;
				case 0xBF:
				case 0x6b:
					c2 = 0x02;
					break;
				case 0xDA:
				case 0x6c:
					c2 = 0x01;
					break;
				case 0xC0:
				case 0x6d:
					c2 = 0x03;
					break;
				case 0xC4:
				case 0x71:
					c2 = 0x06;
					break;
				case 0xC3:
				case 0x74:
					c2 = 0x19;
					break;
				case 0xB4:
				case 0x75:
					c2 = 0x17;
					break;
				case 0xB3:
				case 0x78:
					c2 = 0x05;
					break;
				case 0x80:
					c2 = 0x02;
					break;
				case 0x0F:
				case 0x0E:
				case 0xF2:
				case 0x07:
					loop = FALSE;
					haveEscape = TRUE;
					c1 = c2;
					break;
				default:
					loop = FALSE;
					c1 = c2;
					break;
				}
				if (loop)
				{
					if (c2 != 0x30 && c2 != 0x42)
						WriteFile(lpts->stdo, &c2, 1, (DWORD *) & ret, NULL);
					ret = t_recv(lpts->sock, &c2, 1, 0);
					if (ret <= 0)
						break;
					continue;
				}
				else
					break;
			}
			if (haveEscape || !haveSymbol)
				continue;
		}
#endif
		else if ((c1 == 0x1B))
		{
			ret = t_recv(lpts->sock, &c1, 1, 0);
			if (ret <= 0)
				break;
#ifdef SUPPORT_SYMB
#ifdef SUPPORT_JPNK
			if (lpts->kanji != KANJI_JIS7 && (c1 == '(' || c1 == ')'))
#else
			if ((c1 == '(' || c1 == ')'))
#endif
			{
				ret = t_recv(lpts->sock, &c2, 1, 0);
				if (ret <= 0)
					break;
				if (c1 != ')' || c2 != '\x42')
				{
					haveSymbol |= SYMBOL_GL;
					haveEscape = TRUE;
					c1 = c2;
				}
				else
					continue;
				continue;
			}
			else
#endif

#ifdef SUPPORT_JPNK
				/* JIS�R�[�h���ǂ������ׂ� */
			if (lpts->kanji == KANJI_JIS7 && c1 == '$')
			{
				/* �����C���Ȃ�Ί������[�h�ֈڍs���� */
				ret = t_recv(lpts->sock, &c2, 1, 0);
				if (ret <= 0)
					break;
				if (c2 == 'B')
				{
					dbcs = TRUE;
					continue;
				}
			}
			else if (lpts->kanji == KANJI_JIS7 && c1 == '(')
			{
				/* �����A�E�g�Ȃ�ΕW�����[�h�ֈڍs���� */
				ret = t_recv(lpts->sock, &c2, 1, 0);
				if (ret <= 0)
					break;
				if (c2 == 'B' || c2 == 'J')
				{
					dbcs = FALSE;
					continue;
				}
			}
			else
#endif
				/* �G�X�P�[�v�V�[�P���X�Ȃ�΃R���\�[���������s�� */
			if (c1 == '>' || c1 == '7' || c1 == '8' || c1 == '=' || c1 == '~')
			{
				continue;
			}
			else if (c1 == 'D')
			{
				GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
				mov_rct.Left = 0;
				mov_rct.Right = csbi_now.dwSize.X - 1;
				if (scr_rct.Top == -1)
				{
					mov_rct.Top = csbi_now.srWindow.Top;
					mov_rct.Bottom = csbi_now.srWindow.Bottom;
				}
				else
				{
					mov_rct.Top = csbi_now.srWindow.Top + scr_rct.Top;
					mov_rct.Bottom = csbi_now.srWindow.Top + scr_rct.Bottom;
				}
				if (csbi_now.dwCursorPosition.Y < mov_rct.Bottom)
					csbi_now.dwCursorPosition.Y++;
				else
				{
					mov_rct.Top++;
					coord.X = 0;
					coord.Y = mov_rct.Top - 1;
					ci.Char.AsciiChar = ' ';
					ci.Attributes = csbi_now.wAttributes;
					ScrollConsoleScreenBuffer(lpts->stdo, &mov_rct, NULL,
						coord, &ci);
				}
				SetConsoleCursorPosition(lpts->stdo,
					csbi_now.dwCursorPosition);
				continue;
			}
			else if (c1 == '#')
			{
				ret = t_recv(lpts->sock, &c2, 1, 0);
				if (ret <= 0)
					break;
				continue;
			}
			else if (c1 == 'E')
			{
				GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
				coord = csbi_now.dwCursorPosition;
				coord.X = 0;
				coord.Y++;
				SetConsoleCursorPosition(lpts->stdo, coord);
				continue;
			}
			else if (c1 == 'H')
			{
				c1 = '\t';
			}
			else if (c1 == 'M')
			{
				GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
				mov_rct.Left = 0;
				mov_rct.Right = csbi_now.dwSize.X - 1;
				if (scr_rct.Top == -1)
				{
					mov_rct.Top = csbi_now.srWindow.Top;
					mov_rct.Bottom = csbi_now.srWindow.Bottom;
				}
				else
				{
					mov_rct.Top = csbi_now.srWindow.Top + scr_rct.Top;
					mov_rct.Bottom = csbi_now.srWindow.Top + scr_rct.Bottom;
				}
				if (csbi_now.dwCursorPosition.Y > mov_rct.Top)
					csbi_now.dwCursorPosition.Y--;
				else
				{
					mov_rct.Bottom--;
					coord.X = 0;
					coord.Y = mov_rct.Top + 1;
					ci.Char.AsciiChar = ' ';
					ci.Attributes = csbi_now.wAttributes;
					ScrollConsoleScreenBuffer(lpts->stdo, &mov_rct, NULL,
						coord, &ci);
				}
				SetConsoleCursorPosition(lpts->stdo,
					csbi_now.dwCursorPosition);
				continue;
			}
			else if (c1 == ']')
			{
				int v = -1;
				int n = 0;
				CHAR temp[256];
				for (;;)
				{
					ret = t_recv(lpts->sock, &c2, 1, 0);
					if (ret <= 0)
						break;
					if (!isdigit(c2))
						break;
					if (v == -1)
						v = c2 - '0';
					else
						v = v * 10 + c2 - '0';
				}
				for (;;)
				{
					ret = t_recv(lpts->sock, &c2, 1, 0);
					if (ret <= 0)
						break;
					if (c2 < 0x1F)
					{
						if (v <= 2)
						{
							temp[n++] = 0;
							SetConsoleTitle(temp);
						}
						break;
					}
					else if (v < 2 && n < sizeof(temp) - 1)
						temp[n++] = c2;
				}
				continue;
			}
			else if (c1 == '[')
			{
				int m = 0;
				int v[6];
				int c;
				int n;
				BOOL haveNext;
				for (c = 0; c < 6; c++)
					v[c] = -1;
				n = 0;
				haveNext = TRUE;
				for (;;)
				{
					ret = t_recv(lpts->sock, &c2, 1, 0);
					if (ret <= 0)
						break;
#ifdef DEBUG_ESC
					if (isalpha(c2))
					{
						FILE *pFile = fopen("test.log", "a");
						fprintf(pFile, "%c,%d,%d\n", c2, v[0], v[1]);
						fclose(pFile);
					}
#endif
					switch (c2)
					{
					case '0':
					case '1':
					case '2':
					case '3':
					case '4':
					case '5':
					case '6':
					case '7':
					case '8':
					case '9':
						if (v[n] == -1)
							v[n] = c2 - '0';
						else
							v[n] = v[n] * 10 + c2 - '0';
						break;
					case ';':
						n++;
						break;
					case '>':
					case '?':
						m = c2;
						break;
					case 'r':
						if (v[0] == -1)
						{
							scr_rct.Top = -1;
							scr_rct.Bottom = -1;
						}
						else
						{
							GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
							scr_rct.Left = 0;
							scr_rct.Right = csbi_now.dwSize.X - 1;
							if (v[0] != -1)
								scr_rct.Top = v[0] - 1;
							if (v[1] != -1)
								scr_rct.Bottom = v[1] - 1;
						}
						haveNext = FALSE;
						break;
#ifdef SUPPORT_GPMP
					case 'n':
						if (v[0] == 6)
						{
							GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
							sprintf(sbuf, "\x1b[%d;%dR",
								csbi_now.dwCursorPosition.Y + 1,
								csbi_now.dwCursorPosition.X + 1);
							t_send(lpts->sock, sbuf, strlen(sbuf), 0);
						}
						haveNext = FALSE;
						break;
#endif
					case 'c':
						switch(m)
						{
						case '\0':
							strcpy(sbuf, "\x1B[?1;2c");
							t_send(lpts->sock, sbuf, strlen(sbuf), 0);
							break;
						case '>':
							//strcpy(sbuf, "\033[>32;10;2c");
							//t_send(lpts->sock, sbuf, strlen(sbuf), 0);
							break;
						}
						haveNext = FALSE;
						break;
					case 't':
#ifdef SUPPORT_PIPE
						if (GetFileType(lpts->stdo) == FILE_TYPE_PIPE)
							break;
#endif
						switch (v[0])
						{
						case 8:
							GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
							if (v[1] != -1)
								csbi_now.srWindow.Bottom =
									csbi_now.srWindow.Top + v[1] - 1;
							if (v[2] != -1)
								csbi_now.srWindow.Right =
									csbi_now.srWindow.Left + v[2] - 1;
							RESERVE_IME(lpts, csbi_now);
							SetConsoleWindowInfo(lpts->stdo, TRUE,
								&csbi_now.srWindow);
							break;
						case 14:
							t_send(lpts->sock, "\x1b[4;640;480t", 12, 0);
							break;
						case 18:
							GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
							RESTORE_IME(lpts, csbi_now);
							w = csbi_now.srWindow.Right -
								csbi_now.srWindow.Left + 1;
							h = csbi_now.srWindow.Bottom -
								csbi_now.srWindow.Top + 1;
							sprintf(sbuf, "\x1b[8;%u;%u;t", h, w);
							t_send(lpts->sock, sbuf, strlen(sbuf), 0);
							break;
						}
						haveNext = FALSE;
						break;
					case 'h':
						if (m == '?')
						{
							for (c = 0; c <= n; c++)
							{
								switch (v[c])
								{
								case 1:
									lpts->cursor = TRUE;
									break;
								case 3:
									GetConsoleScreenBufferInfo(lpts->stdo,
										&csbi_now);
									w = csbi_now.dwSize.X;
									h = csbi_now.srWindow.Bottom
										- csbi_now.srWindow.Top + 1;
									dwConSize = w * (h + 1);
									coord.X = 0;
									coord.Y = csbi_now.srWindow.Top;
									FillConsoleOutputCharacter(lpts->stdo,
										' ', dwConSize, coord, &dwWritten);
									FillConsoleOutputAttribute(lpts->stdo,
										csbi_now.wAttributes, dwConSize,
										coord, &dwWritten);
									SetConsoleCursorPosition(lpts->stdo,
										csbi_now.dwCursorPosition);
									csbi_now.dwSize.X = 132;
									SetConsoleScreenBufferSize(lpts->stdo,
										csbi_now.dwSize);
									csbi_now.srWindow.Right =
										csbi_now.srWindow.Left + 131;
									SetConsoleWindowInfo(lpts->stdo, TRUE,
										&csbi_now.srWindow);
									break;
								case 5:
									attr_new =
										((attr_new & FOREGROUND_MASK) << 4) |
										((attr_new & BACKGROUND_MASK) >> 4);
									SetConsoleTextAttribute(lpts->stdo,
										attr_new);
									break;
								case 9:
									break;
								case 25:
									GetConsoleCursorInfo(lpts->stdo,
										&cci_new);
									cci_new.bVisible = TRUE;
									SetConsoleCursorInfo(lpts->stdo,
										&cci_new);
									break;
								case 47:
#ifdef SUPPORT_SWAP
									if (lpts->stdo == lpts->alto)
										break;
									GetConsoleScreenBufferInfo(hswap,
										&csbi_now);
									csbi_swp = csbi_now;
									coord.X =
										csbi_now.srWindow.Right -
										csbi_now.srWindow.Left + 1;
									coord.Y =
										csbi_now.srWindow.Bottom -
										csbi_now.srWindow.Top + 1;
									mov_rct.Top = 0;
									mov_rct.Left = 0;
									mov_rct.Bottom = coord.Y - 1;
									mov_rct.Right = coord.X - 1;
									attr_new = attr_old;
									SetConsoleTextAttribute(lpts->alto,
										attr_new);
									SetConsoleScreenBufferSize(lpts->alto,
										coord);
									SetConsoleWindowInfo(lpts->alto, TRUE,
										&mov_rct);
									SetConsoleActiveScreenBuffer(lpts->alto);
									lpts->stdo = lpts->alto;
#else
									coord.X = 0;
									coord.Y = 0;
									SetConsoleCursorPosition(lpts->stdo,
										coord);
#endif
									break;
								case 1000:
									lpts->mouse = TRUE;
									break;
								case 1001:
									lpts->mouse = FALSE;
									break;
								default:
									break;
								}
							}
						}
						else if (m == '>' && v[0] == 5)
						{
							GetConsoleCursorInfo(lpts->stdo, &cci_new);
							cci_new.bVisible = FALSE;
							SetConsoleCursorInfo(lpts->stdo, &cci_new);
						}
						else if (v[0] == 4)
							lpts->insert = TRUE;
						haveNext = FALSE;
						break;
					case 'l':
						if (m == '?')
						{
							for (c = 0; c <= n; c++)
							{
								switch (v[c])
								{
								case 1:
									lpts->cursor = FALSE;
									break;
								case 3:
									GetConsoleScreenBufferInfo(lpts->stdo,
										&csbi_now);
									w = csbi_now.dwSize.X;
									h = csbi_now.srWindow.Bottom
										- csbi_now.srWindow.Top + 1;
									dwConSize = w * (h + 1);
									coord.X = 0;
									coord.Y = csbi_now.srWindow.Top;
									FillConsoleOutputCharacter(lpts->stdo,
										' ', dwConSize, coord, &dwWritten);
									FillConsoleOutputAttribute(lpts->stdo,
										csbi_now.wAttributes, dwConSize,
										coord, &dwWritten);
									SetConsoleCursorPosition(lpts->stdo,
										csbi_now.dwCursorPosition);
									csbi_now.srWindow.Right =
										csbi_now.srWindow.Left + 79;
									SetConsoleWindowInfo(lpts->stdo, TRUE,
										&csbi_now.srWindow);
									csbi_now.dwSize.X = 80;
									SetConsoleScreenBufferSize(lpts->stdo,
										csbi_now.dwSize);
									break;
								case 5:
									attr_new =
										((attr_new & FOREGROUND_MASK) << 4) |
										((attr_new & BACKGROUND_MASK) >> 4);
									SetConsoleTextAttribute(lpts->stdo,
										attr_new);
									break;
								case 25:
									GetConsoleCursorInfo(lpts->stdo,
										&cci_new);
									cci_new.bVisible = FALSE;
									SetConsoleCursorInfo(lpts->stdo,
										&cci_new);
									break;
								case 47:
#ifdef SUPPORT_SWAP
									if (lpts->stdo != lpts->alto)
										break;
									GetConsoleScreenBufferInfo(lpts->alto,
										&csbi_now);
									lpts->stdo = hswap;
									csbi_swp.srWindow.Left =
										csbi_now.srWindow.Left;
									csbi_swp.srWindow.Right =
										csbi_now.srWindow.Right;
									SetConsoleActiveScreenBuffer(lpts->stdo);
									scr_rct.Top = -1;
									scr_rct.Bottom = -1;
									lpts->curp = -1;
#endif
									break;
								case 1000:
									lpts->mouse = FALSE;
									break;
								default:
									break;
								}
							}
						}
						else if (m == '>' && v[0] == 5)
						{
							GetConsoleCursorInfo(lpts->stdo, &cci_new);
							cci_new.bVisible = TRUE;
							SetConsoleCursorInfo(lpts->stdo, &cci_new);
						}
						else if (v[0] == 4)
							lpts->insert = FALSE;
						haveNext = FALSE;
						break;
					case 'm':
						for (c = 0; c <= n; c++)
						{
							if (v[c] == -1 || v[c] == 0)
								attr_new = attr_old;
							else if (v[c] == 1)
								attr_new |= FOREGROUND_INTENSITY;
							else if (v[c] == 4)
								attr_new |= FOREGROUND_INTENSITY;
							else if (v[c] == 5)
								attr_new |= FOREGROUND_INTENSITY;
							else if (v[c] == 7)
								attr_new =
									((attr_new & FOREGROUND_MASK) << 4) |
									((attr_new & BACKGROUND_MASK) >> 4);
							else if (v[c] == 10)
								haveSymbol |= SYMBOL_SC;
							else if (v[c] == 11)
								haveSymbol &= ~SYMBOL_SC;
							else if (v[c] == 22)
								attr_new &= ~FOREGROUND_INTENSITY;
							else if (v[c] == 24)
								attr_new &= ~FOREGROUND_INTENSITY;
							else if (v[c] == 25)
								attr_new &= ~FOREGROUND_INTENSITY;
							else if (v[c] == 27)
								attr_new =
									((attr_new & FOREGROUND_MASK) << 4) |
									((attr_new & BACKGROUND_MASK) >> 4);
							else if (v[c] >= 30 && v[c] <= 37)
							{
								attr_new = (attr_new & BACKGROUND_MASK)
									| FOREGROUND_INTENSITY;
								if ((v[c] - 30) & 1)
									attr_new |= FOREGROUND_RED;
								if ((v[c] - 30) & 2)
									attr_new |= FOREGROUND_GREEN;
								if ((v[c] - 30) & 4)
									attr_new |= FOREGROUND_BLUE;
							}
							//else if (v[c] == 39)
							//attr_new = (~attr_new & BACKGROUND_MASK);
							else if (v[c] >= 40 && v[c] <= 47)
							{
								attr_new = (attr_new & FOREGROUND_MASK)
									| BACKGROUND_INTENSITY;
								if ((v[c] - 40) & 1)
									attr_new |= BACKGROUND_RED;
								if ((v[c] - 40) & 2)
									attr_new |= BACKGROUND_GREEN;
								if ((v[c] - 40) & 4)
									attr_new |= BACKGROUND_BLUE;
							}
							//else if (v[c] == 49)
							//attr_new = (~attr_new & FOREGROUND_MASK);
							else if (v[c] == 100)
								attr_new = attr_old;
						}
						SetConsoleTextAttribute(lpts->stdo, attr_new);
						haveNext = FALSE;
						break;
					case '@':
						if (v[0] == -1)
							v[0] = 1;
						GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
						ci.Char.AsciiChar = ' ';
						ci.Attributes = csbi_now.wAttributes;
						mov_rct.Top = csbi_now.dwCursorPosition.Y;
						mov_rct.Bottom = mov_rct.Top;
						mov_rct.Left = csbi_now.dwCursorPosition.X;
						mov_rct.Right = csbi_now.dwSize.X - v[0];
						coord.X = csbi_now.dwCursorPosition.X + v[0];
						coord.Y = csbi_now.dwCursorPosition.Y;
						ScrollConsoleScreenBuffer(lpts->stdo, &mov_rct, NULL,
							coord, &ci);
						SetConsoleCursorPosition(lpts->stdo,
							csbi_now.dwCursorPosition);
						haveNext = FALSE;
						break;
					case 'X':
						GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
						coord = csbi_now.dwCursorPosition;
						if (v[0] == -1)
							dwConSize = 1;
						else
							dwConSize = v[0];
						FillConsoleOutputCharacter(lpts->stdo, ' ',
							dwConSize, coord, &dwWritten);
						FillConsoleOutputAttribute(lpts->stdo,
							csbi_now.wAttributes, dwConSize, coord,
							&dwWritten);
						SetConsoleCursorPosition(lpts->stdo,
							csbi_now.dwCursorPosition);
						haveNext = FALSE;
						break;
					case 'K':
						GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
						coord = csbi_now.dwCursorPosition;
						switch (v[0])
						{
						default:
						case 0:
							dwConSize = csbi_now.dwSize.X - coord.X;
							break;
						case 1:
							dwConSize = coord.X;
							coord.X = 0;
							break;
						case 2:
							dwConSize = csbi_now.dwSize.X;
							coord.X = 0;
							break;
						}
						FillConsoleOutputCharacter(lpts->stdo, ' ',
							dwConSize, coord, &dwWritten);
						FillConsoleOutputAttribute(lpts->stdo,
							csbi_now.wAttributes, dwConSize, coord,
							&dwWritten);
						SetConsoleCursorPosition(lpts->stdo,
							csbi_now.dwCursorPosition);
						haveNext = FALSE;
						break;
					case '*':
					case 'J':
						GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
						w = csbi_now.dwSize.X;
						h = csbi_now.srWindow.Bottom
							- csbi_now.srWindow.Top + 1;
						coord = csbi_now.dwCursorPosition;
						switch (v[0])
						{
						default:
						case 0:
							dwConSize = w * (h - coord.Y) - coord.X;
							coord.X = 0;
							break;
						case 1:
							dwConSize = w * coord.Y + coord.X;
							coord.X = 0;
							coord.Y = csbi_now.srWindow.Top;
							break;
						case 2:
							dwConSize = w * (h + 1);
							coord.X = 0;
							coord.Y = csbi_now.srWindow.Top;
							break;
						}
						mov_rct.Left = 0;
						mov_rct.Top = 0;
						mov_rct.Right = w;
						mov_rct.Bottom = h;
						FillConsoleOutputCharacter(lpts->stdo, ' ',
							dwConSize, coord, &dwWritten);
						FillConsoleOutputAttribute(lpts->stdo,
							csbi_now.wAttributes, dwConSize, coord,
							&dwWritten);
						SetConsoleCursorPosition(lpts->stdo,
							csbi_now.dwCursorPosition);
						haveNext = FALSE;
						break;
					case 'G':
					case '`':
						GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
						coord = csbi_now.dwCursorPosition;
						if (lpts->curp != -1)
						{
							coord.X = csbi_now.dwSize.X - 1;
							coord.Y = lpts->curp;
						}
						if (v[0] == -1)
							coord.X = csbi_now.srWindow.Left;
						else
							coord.X = csbi_now.srWindow.Left + v[0] - 1;
						if (coord.X < csbi_now.srWindow.Left)
							coord.X = csbi_now.srWindow.Left;
						else if (coord.X > csbi_now.srWindow.Right)
							coord.X = csbi_now.srWindow.Right;
						lpts->curp = -1;
						SetConsoleCursorPosition(lpts->stdo, coord);
						haveNext = FALSE;
						break;
					case 'd':
						GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
						RESTORE_IME(lpts, csbi_now);
						coord = csbi_now.dwCursorPosition;
						if (v[0] == -1)
							coord.Y = csbi_now.srWindow.Top;
						else
							coord.Y = csbi_now.srWindow.Top + v[0] - 1;
						if (coord.Y < csbi_now.srWindow.Top)
							coord.Y = csbi_now.srWindow.Top;
						else if (coord.Y > csbi_now.srWindow.Bottom)
							coord.Y = csbi_now.srWindow.Bottom;
						lpts->curp = -1;
						SetConsoleCursorPosition(lpts->stdo, coord);
						haveNext = FALSE;
						break;
					case 'e':
					case 'A':
						GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
						RESTORE_IME(lpts, csbi_now);
						coord = csbi_now.dwCursorPosition;
						//if (lpts->curp != -1)
						//{
						//  coord.X = csbi_now.dwSize.X - 1;
						//  coord.Y = lpts->curp;
						//}
						if (v[0] == -1)
							coord.Y--;
						else
							coord.Y -= v[0];
						if (scr_rct.Top != -1)
						{
							if (coord.Y < csbi_now.srWindow.Top + scr_rct.Top)
								coord.Y = csbi_now.srWindow.Top + scr_rct.Top;
							else if (coord.Y >
								csbi_now.srWindow.Top + scr_rct.Bottom)
								coord.Y =
									csbi_now.srWindow.Top + scr_rct.Bottom;
						}
						if (coord.Y < csbi_now.srWindow.Top)
							coord.Y = csbi_now.srWindow.Top;
						else if (coord.Y > csbi_now.srWindow.Bottom)
							coord.Y = csbi_now.srWindow.Bottom;
						lpts->curp = -1;
						SetConsoleCursorPosition(lpts->stdo, coord);
						haveNext = FALSE;
						break;
					case 'B':
						GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
						RESTORE_IME(lpts, csbi_now);
						coord = csbi_now.dwCursorPosition;
						//if (lpts->curp != -1)
						//{
						//  coord.X = csbi_now.dwSize.X - 1;
						//  coord.Y = lpts->curp;
						//}
						if (v[0] == -1)
							coord.Y++;
						else
							coord.Y += v[0];
						if (scr_rct.Top != -1)
						{
							if (coord.Y < csbi_now.srWindow.Top + scr_rct.Top)
								coord.Y = csbi_now.srWindow.Top + scr_rct.Top;
							else if (coord.Y >
								csbi_now.srWindow.Top + scr_rct.Bottom)
								coord.Y =
									csbi_now.srWindow.Top + scr_rct.Bottom;
						}
						if (coord.Y < csbi_now.srWindow.Top)
							coord.Y = csbi_now.srWindow.Top;
						else if (coord.Y > csbi_now.srWindow.Bottom)
							coord.Y = csbi_now.srWindow.Bottom;
						lpts->curp = -1;
						SetConsoleCursorPosition(lpts->stdo, coord);
						haveNext = FALSE;
						break;
					case 'C':
						GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
						coord = csbi_now.dwCursorPosition;
						if (v[0] == -1)
							coord.X++;
						else
							coord.X += v[0];
						if (coord.X < csbi_now.srWindow.Left)
							coord.X = csbi_now.srWindow.Left;
						else if (coord.X > csbi_now.srWindow.Right)
							coord.X = csbi_now.srWindow.Right;
						lpts->curp = -1;
						SetConsoleCursorPosition(lpts->stdo, coord);
						haveNext = FALSE;
						break;
					case 'a':
					case 'D':
						GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
						coord = csbi_now.dwCursorPosition;
						if (lpts->curp != -1)
						{
							coord.X = csbi_now.dwSize.X - 1;
							coord.Y = lpts->curp;
						}
						if (v[0] == -1)
							coord.X--;
						else
							coord.X -= v[0];
						if (coord.X < csbi_now.srWindow.Left)
							coord.X = csbi_now.srWindow.Left;
						else if (coord.X > csbi_now.srWindow.Right)
							coord.X = csbi_now.srWindow.Right;
						lpts->curp = -1;
						SetConsoleCursorPosition(lpts->stdo, coord);
						haveNext = FALSE;
						break;
					case 'L':
						GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
						if (v[0] == -1)
							v[0] = 1;
						mov_rct.Top = csbi_now.dwCursorPosition.Y;
						if (scr_rct.Top == -1)
							mov_rct.Bottom = csbi_now.srWindow.Bottom;
						else
							mov_rct.Bottom =
								csbi_now.srWindow.Top + scr_rct.Bottom;
						mov_rct.Left = 0;
						mov_rct.Right = csbi_now.dwSize.X - 1;
						coord.X = 0;
						coord.Y = mov_rct.Top + v[0];
						ci.Char.AsciiChar = ' ';
						ci.Attributes = csbi_now.wAttributes;
						ScrollConsoleScreenBuffer(lpts->stdo, &mov_rct,
							&mov_rct, coord, &ci);
						SetConsoleCursorPosition(lpts->stdo,
							csbi_now.dwCursorPosition);
						haveNext = FALSE;
						break;
					case 'M':
						GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
						if (v[0] == -1)
							v[0] = 1;
						mov_rct.Top = csbi_now.dwCursorPosition.Y;
						if (scr_rct.Top == -1)
							mov_rct.Bottom = csbi_now.srWindow.Bottom;
						else
							mov_rct.Bottom =
								csbi_now.srWindow.Top + scr_rct.Bottom;
						mov_rct.Left = 0;
						mov_rct.Right = csbi_now.dwSize.X - 1;
						coord.X = 0;
						coord.Y = mov_rct.Top - v[0];
						ci.Char.AsciiChar = ' ';
						ci.Attributes = csbi_now.wAttributes;
						ScrollConsoleScreenBuffer(lpts->stdo, &mov_rct,
							&mov_rct, coord, &ci);
						SetConsoleCursorPosition(lpts->stdo,
							csbi_now.dwCursorPosition);
						haveNext = FALSE;
						break;
					case 'P':
						if (v[0] == -1)
							v[0] = 1;
						GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
						ci.Char.AsciiChar = ' ';
						ci.Attributes = csbi_now.wAttributes;
						mov_rct.Top = csbi_now.dwCursorPosition.Y;
						mov_rct.Bottom = mov_rct.Top;
						mov_rct.Left = csbi_now.dwCursorPosition.X + v[0];
						mov_rct.Right = csbi_now.dwSize.X;
						coord.X = csbi_now.dwCursorPosition.X;
						coord.Y = csbi_now.dwCursorPosition.Y;
						ScrollConsoleScreenBuffer(lpts->stdo, &mov_rct, NULL,
							coord, &ci);
						SetConsoleCursorPosition(lpts->stdo,
							csbi_now.dwCursorPosition);
						haveNext = FALSE;
						break;
					case 's':
						GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
						attr_set = csbi_now.wAttributes;
						haveNext = FALSE;
						break;
					case 'u':
						SetConsoleTextAttribute(lpts->stdo, attr_set);
						haveNext = FALSE;
						break;
					case 'S':
						break;
					case 'f':
					case 'H':
						GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
						coord = csbi_now.dwCursorPosition;
						if (lpts->curp != -1)
						{
							coord.X = csbi_now.dwSize.X - 1;
							coord.Y = lpts->curp;
						}
						if (v[0] != -1)
						{
							if (v[1] != -1)
							{
								coord.Y = csbi_now.srWindow.Top + v[0] - 1;
								coord.X = v[1] - 1;
							}
							else
								coord.X = v[0] - 1;
						}
						else
						{
							coord.X = 0;
							coord.Y = csbi_now.srWindow.Top;
						}
						if (coord.X < csbi_now.srWindow.Left)
							coord.X = csbi_now.srWindow.Left;
						else if (coord.X > csbi_now.srWindow.Right)
							coord.X = csbi_now.srWindow.Right;
						if (coord.Y < csbi_now.srWindow.Top)
							coord.Y = csbi_now.srWindow.Top;
						else if (coord.Y > csbi_now.srWindow.Bottom)
							coord.Y = csbi_now.srWindow.Bottom;
						lpts->curp = -1;
						SetConsoleCursorPosition(lpts->stdo, coord);
						haveNext = FALSE;
						break;
					case 0x1B:
						haveEscape = TRUE;
						haveNext = FALSE;
						c1 = c2;
						break;
					default:
						haveNext = FALSE;
						break;
					}
					if (n == 6 || !haveNext)
						break;
				}
				continue;
			}
		}

#ifdef DEBUG_TXT
		{
			FILE *pFile = fopen("test.log", "a");
			if (c1)
				fprintf(pFile, "%02x,%c\n", c1, c1);
			else
				fprintf(pFile, "%02x,ZERO\n", c1);
			fclose(pFile);
		}
#endif
		if (c1)
		{
			if (lpts->insert)
			{
				GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
				ci.Char.AsciiChar = ' ';
				ci.Attributes = csbi_now.wAttributes;
				mov_rct.Top = csbi_now.dwCursorPosition.Y;
				mov_rct.Bottom = mov_rct.Top;
				mov_rct.Left = csbi_now.dwCursorPosition.X;
				mov_rct.Right = csbi_now.dwSize.X - 1;
				coord.X = csbi_now.dwCursorPosition.X + 1;
				coord.Y = csbi_now.dwCursorPosition.Y;
				ScrollConsoleScreenBuffer(lpts->stdo, &mov_rct, NULL,
					coord, &ci);
			}
#ifdef SUPPORT_JPNK
			/* �������[�h�Ȃ�Ύ��̕������擾����SJIS�ɕϊ����� */
			if (dbcs)
			{
				if ((lc & 0x80) == 0)
				{
					ret = t_recv(lpts->sock, &c2, 1, 0);
					if (ret <= 0)
						break;
					if (c2 == 0x1b)
					{
						haveEscape = TRUE;
						lc = c1;
						c1 = c2;
						continue;
					}
				}
				else
				{
					c2 = c1;
					c1 = lc;
				}
				GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
				coord = csbi_now.dwCursorPosition;
				if (lpts->curp == -1)
					lpts->curp = coord.Y;
				if (coord.Y <= csbi_now.srWindow.Bottom)
				{
					switch (lpts->kanji)
					{
					case KANJI_JIS7:
						if ((c1 % 2) == 0)
							c2 += 0x7D;
						else
							c2 += 0x1F;
						if (c2 > 0x7E)
							c2++;
						if (c1 < 0x5F)
							c1 = (c1 + 1) / 2 + 0x70;
						else
							c1 = (c1 + 1) / 2 + 0xB0;
						WriteFile(lpts->stdo, &c1, 1, (DWORD *) & ret, NULL);
						if (!haveEscape)
							WriteFile(lpts->stdo, &c2, 1, (DWORD *) & ret,
								NULL);
						break;
					case KANJI_SJIS:
						WriteFile(lpts->stdo, &c1, 1, (DWORD *) & ret, NULL);
						if (!haveEscape)
							WriteFile(lpts->stdo, &c2, 1, (DWORD *) & ret,
								NULL);
						dbcs = FALSE;
						break;
					case KANJI_EUCJ:
						if ((unsigned char)c1 != 0x8E)
						{
							if ((unsigned char)c1 % 2 == 0)
								c2 -= 0x02;
							else
								c2 -=
									((unsigned char)c2 > 0xdf) ? 0x60 : 0x61;
							if ((unsigned char)c1 < 0xdf)
								c1 = ((unsigned char)c1 + 1) / 2 + 0x30;
							else
								c1 = ((unsigned char)c1 + 1) / 2 + 0x70;
							WriteFile(lpts->stdo, &c1, 1, (DWORD *) & ret,
								NULL);
							if (!haveEscape)
								WriteFile(lpts->stdo, &c2, 1,
									(DWORD *) & ret, NULL);
							dbcs = FALSE;
						}
						else
						{
							WriteFile(lpts->stdo, &c2, 1, (DWORD *) & ret,
								NULL);
							dbcs = FALSE;
						}
						break;
					}
				}
				if (!haveEscape)
					c1 = 0;
			}
			else
#endif
			if (c1 == '\t')
			{
				GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
				coord.Y = csbi_now.dwCursorPosition.Y;
				coord.X = 8 * (int)((csbi_now.dwCursorPosition.X + 8) / 8);
				SetConsoleCursorPosition(lpts->stdo, coord);
			}
			else if (c1 == '\x08')
			{
				GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
				coord.Y = csbi_now.dwCursorPosition.Y;
				coord.X = csbi_now.dwCursorPosition.X - 1;
				SetConsoleCursorPosition(lpts->stdo, coord);
			}
			else if (c1 == '\n')
			{
				GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
				RESTORE_IME(lpts, csbi_now);
				coord = csbi_now.dwCursorPosition;
				if (coord.Y == scr_rct.Bottom)
				{
					mov_rct = scr_rct;
					mov_rct.Top++;
					coord.X = 0;
					coord.Y = scr_rct.Top;
					ci.Char.AsciiChar = ' ';
					ci.Attributes = csbi_now.wAttributes;
					ScrollConsoleScreenBuffer(lpts->stdo, &mov_rct,
						NULL, coord, &ci);
				}
				else if (coord.Y < csbi_now.srWindow.Bottom)
				{
					coord.Y++;
					SetConsoleCursorPosition(lpts->stdo, coord);
				}
				else if (coord.Y < csbi_now.dwSize.Y - 2)
				{
					RESERVE_IME(lpts, csbi_now);
					mov_rct = csbi_now.srWindow;
					mov_rct.Top++;
					mov_rct.Bottom++;
					SetConsoleWindowInfo(lpts->stdo, TRUE, &mov_rct);
					coord.X = 0;
					coord.Y = csbi_now.srWindow.Bottom + 1;
					dwConSize = csbi_now.dwSize.X;
					FillConsoleOutputCharacter(lpts->stdo, ' ',
						dwConSize, coord, &dwWritten);
					FillConsoleOutputAttribute(lpts->stdo,
						csbi_now.wAttributes, dwConSize, coord, &dwWritten);
					coord.Y = csbi_now.dwCursorPosition.Y + 1;
					SetConsoleCursorPosition(lpts->stdo, coord);
				}
				else
				{
					RESERVE_IME(lpts, csbi_now);
					mov_rct.Left = 0;
					mov_rct.Top = 0;
					mov_rct.Right = csbi_now.dwSize.X;
					mov_rct.Bottom = csbi_now.dwSize.Y;
					coord.X = 0;
					coord.Y = -1;
					ci.Char.AsciiChar = ' ';
					ci.Attributes = csbi_now.wAttributes;
					ScrollConsoleScreenBuffer(lpts->stdo, &mov_rct,
						&mov_rct, coord, &ci);
				}
				if (lpts->line & LINE_AUTO)
					lpts->line |= LINE_LF;
			}
			else if (c1 == '\r')
			{
				GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
				coord = csbi_now.dwCursorPosition;
				if (lpts->curp != -1 && lc != '\n')
				{
					coord.X = 0;
					coord.Y = lpts->curp;
					SetConsoleCursorPosition(lpts->stdo, coord);
				}
				else
					WriteFile(lpts->stdo, &c1, 1, (DWORD *) & ret, NULL);
				if (lpts->line & LINE_AUTO)
					lpts->line |= LINE_CR;
			}
			else
			{
				/* ����ȊO�Ȃ�΂��̂܂ܕW���o�͂֏������� */
				WriteFile(lpts->stdo, &c1, 1, (DWORD *) & ret, NULL);
#ifdef SUPPORT_JPNK
				if (lpts->kanji != KANJI_JIS7)
					dbcs = FALSE;
#endif
			}

			if (c1 != '\r')
			{
				GetConsoleScreenBufferInfo(lpts->stdo, &csbi_now);
				coord = csbi_now.dwCursorPosition;
#ifdef SUPPORT_JPNK
				if (lpts->ime
					&& csbi_now.dwCursorPosition.Y ==
					csbi_now.srWindow.Bottom && lpts->curp != -1)
				{
					coord.X = csbi_now.srWindow.Left;
					coord.Y = csbi_now.srWindow.Top - 1;
					ci.Char.AsciiChar = ' ';
					ci.Attributes = csbi_now.wAttributes;
					ScrollConsoleScreenBuffer(lpts->stdo,
						&csbi_now.srWindow, &csbi_now.srWindow, coord, &ci);
					coord = csbi_now.dwCursorPosition;
					coord.Y--;
					SetConsoleCursorPosition(lpts->stdo, coord);
				}
#endif
				if (coord.X == 0)
					lpts->curp = coord.Y - 1;
				else
					lpts->curp = -1;
			}
		}
		lc = c1;
	}

#ifdef SUPPORT_SWAP
	if (lpts->stdo != hswap)
	{
		lpts->stdo = hswap;
		SetConsoleActiveScreenBuffer(lpts->stdo);
	}
#endif
	SetConsoleTextAttribute(lpts->stdo, attr_old);
	SetConsoleCursorInfo(lpts->stdo, &cci_old);

	if (ret <= 0)
	{

		/* �z�X�g����̐ؒf���� */
		if (lpts->sock != INVALID_SOCKET)
			temp = "\n�z�X�g����ؒf����܂���\n";
		else
			temp = "\n�����ؒf���܂���\n";
		WriteFile(lpts->stdo, temp, strlen(temp), (DWORD *) & ret, NULL);
	}

#ifdef SUPPORT_NTLM
	AuthNTLM(NULL);
#endif

	/* �\�P�b�g��ؒf���� */
	shutdown(lpts->sock, SD_BOTH);
	closesocket(lpts->sock);
	lpts->sock = INVALID_SOCKET;
	return 0;
}

/******************************************************************************
* Function Usage
******************************************************************************/
void
Usage(HANDLE stdo, LPTELNET_STRUCT lpts, BOOL mode)
{
	DWORD ret;					/* �߂�l */
	CHAR *author =
		"sTelNet : Small Telnet Client by �܂���            \n"
		"�g�p�@: [�I�v�V����] [�z�X�g] [�|�[�g]               \n"
		"-----------------------------------------------------\n";
	CHAR *usages = "      �z�X�g     : �A�h���X�������͖��O              \n"
#ifdef SUPPORT_SERV
		"                   (\"-\" �ŃT�[�o�Ƃ��ē���)        \n"
#endif
		"      �|�[�g     : �|�[�g�ԍ��������̓|�[�g��        \n"
		"                   (�K��l 23)                       \n"
		"-----------------------------------------------------\n"
#ifdef SUPPORT_JPNK
		"        -kanji=[sjis|jis7|eucj] ����M�Ɏg�p���銿�� \n"
#endif
		"        -line=[auto|cr|lf|crlf] ���s�R�[�h           \n"
		"        -echo=[on|off]          ���[�J���G�R�[       \n"
#ifdef SUPPORT_NAWS
		"        -naws=[auto|on|off]     �E�B���h�E��       \n"
#endif
		"        -term=[�[����]          �[����(�K��l kterm) \n";
	CHAR *keyhlp =
#ifdef __GNUC__
		"      CTRL-F1  : �w���v�\\��\n"
		"      CTRL-F3  : �ҋ@�\\�P�b�g�쐬\n"
#else
		"      CTRL-F1  : �w���v�\��\n" "      CTRL-F3  : �ҋ@�\�P�b�g�쐬\n"
#endif
		"      CTRL-F4  : �����I��\n"
		"      CTRL-F5  : �����R�[�h�ؑ�\n"
		"      CTRL-F6  : ���[�J���G�R�[�ؑ�\n"
		"      CTRL-F7  : ���s�R�[�h�ؑ�\n"
		"      CTRL-F8  : NAWS�ؑ�\n"
		"      CTRL-F9  : �x���ؑ�\n"
		"      CTRL-F10 : �L�[�ؑ�\n"
		"-----------------------------------------------------\n";
	/* �g�p�@��\������ */
	WriteFile(stdo, author, strlen(author), &ret, NULL);
	if (mode)
		WriteFile(stdo, usages, strlen(usages), &ret, NULL);
	else
	{
		CHAR temp[256];
		WriteFile(stdo, keyhlp, strlen(keyhlp), &ret, NULL);
		strcpy(temp, "�����R�[�h     : ");
		for (ret = 0; js[ret].key != KANJI_NONE; ret++)
			if (lpts->kanji == js[ret].key)
				strcat(temp, js[ret].name);
		strcat(temp, "\n");
		WriteFile(stdo, temp, strlen(temp), &ret, NULL);
		strcpy(temp, "���[�J���G�R�[ : ");
		if (lpts->echo)
			strcat(temp, "on");
		else
			strcat(temp, "off");
		strcat(temp, "\n");
		WriteFile(stdo, temp, strlen(temp), &ret, NULL);
		strcpy(temp, "���s�R�[�h     : ");
		switch (lpts->line & ~LINE_AUTO)
		{
		case LINE_NONE:
			strcat(temp, "auto");
			break;
		case LINE_CR:
			strcat(temp, "cr");
			break;
		case LINE_LF:
			strcat(temp, "lf");
			break;
		case LINE_CRLF:
			strcat(temp, "crlf");
			break;
		}
		strcat(temp, "\n");
		WriteFile(stdo, temp, strlen(temp), &ret, NULL);
		strcpy(temp, "NAWS           : ");
		switch (lpts->naws)
		{
		case NAWS_AUTO:
			strcat(temp, "auto");
			break;
		case NAWS_ON:
			strcat(temp, "on");
			break;
		case NAWS_OFF:
			strcat(temp, "off");
			break;
		}
		strcat(temp, "\n");
		WriteFile(stdo, temp, strlen(temp), &ret, NULL);
		strcpy(temp, "�x��           : ");
		if (lpts->bell)
			strcat(temp, "on");
		else
			strcat(temp, "off");
		strcat(temp, "\n");
		WriteFile(stdo, temp, strlen(temp), &ret, NULL);
	}
}

/******************************************************************************
* Function main
******************************************************************************/
int
main(int argc, char *argv[])
{
	WORD wVerReq;				/* winsock �o�[�W������� */
	WSADATA wsaData;			/* winsock �������f�[�^   */

	DWORD dwMode;				/* ���[�h                 */
	DWORD dwModeOld;			/* ���[�h                 */
	LPSTR serv_name = NULL;		/* �T�[�o��               */
	LPSTR port_name = NULL;		/* �|�[�g��               */
	USHORT nport;				/* �|�[�g��               */
	LPHOSTENT shost;			/* �z�X�g�G���g��         */
	LPSERVENT sserv;			/* �T�[�o�G���g��         */
	SOCKADDR_IN server;			/* �T�[�o�A�h���X         */
	CHAR term[256];				/* �[����                 */
	CHAR temp[256];				/* �G���[���b�Z�[�W       */
	DWORD ret;					/* API�߂�l              */
	TELNET_STRUCT ts;			/* �ʐM�p�����\����       */
	INT count;					/* �ėp�ϐ�               */
	INT argn = 0;				/* �����p�ϐ�             */
	HANDLE hThread;				/* �X���b�h�n���h��       */
	DWORD ThreadID = 0;			/* �X���b�h�h�c           */
#ifdef SUPPORT_ICON
	HWND hWnd = NULL;			/* �E�B���h�E�n���h��     */
	HICON hIcon = NULL, hIconS, hIconB;	/* �A�C�R���n���h��       */
	GETCONSOLEWINDOWPROC pfnGetConsoleWindow;	/* �֐��|�C���^           */
#endif
	CHAR title[256];			/* �E�B���h�E�^�C�g��     */

	/* �ʐM�p�����\���̂����������� */
	memset(&ts, 0x00, sizeof(TELNET_STRUCT));

#ifdef SUPPORT_JPNK
	ts.kanji = KANJI_EUCJ;
#endif
	ts.line = LINE_AUTO;
	ts.bell = FALSE;
	ts.ntlm = TRUE;
	ts.naws = NAWS_AUTO;

	/* �W�����o�̓n���h�����擾���� */
	ts.stdi = GetStdHandle(STD_INPUT_HANDLE);
	ts.stdo = GetStdHandle(STD_OUTPUT_HANDLE);
	ts.alto = ts.stdo;

	ts.curp = -1;
	ts.lock = FALSE;

	ts.serv_port = 0;

	memset(term, 0, sizeof(term));

	/* �����`�F�b�N */
	for (count = 1; count < argc; count++)
	{
		if (argv[count][0] == '-' && argv[count][1] != '\0')
		{
			if (!strncmp(argv[count] + 1, "echo=", 5))
			{
				if (!strcmp(argv[count] + 6, "on"))
					ts.echo = TRUE;
				else if (!strcmp(argv[count] + 6, "off"))
					ts.echo = FALSE;
				else
				{
					Usage(ts.stdo, &ts, TRUE);
					return 0;
				}
			}
			else if (!strncmp(argv[count] + 1, "bell=", 5))
			{
				if (!strcmp(argv[count] + 6, "on"))
					ts.bell = TRUE;
				else if (!strcmp(argv[count] + 6, "off"))
					ts.bell = FALSE;
				else
				{
					Usage(ts.stdo, &ts, TRUE);
					return 0;
				}
			}
#ifdef SUPPORT_NAWS
			else if (!strncmp(argv[count] + 1, "naws=", 5))
			{
				if (!strcmp(argv[count] + 6, "auto"))
					ts.naws = NAWS_AUTO;
				else if (!strcmp(argv[count] + 6, "on"))
					ts.naws = NAWS_ON;
				else if (!strcmp(argv[count] + 6, "off"))
					ts.naws = NAWS_OFF;
				else
				{
					Usage(ts.stdo, &ts, TRUE);
					return 0;
				}
			}
#endif
#ifdef SUPPORT_NTLM
			else if (!strncmp(argv[count] + 1, "ntlm=", 5))
			{
				if (!strcmp(argv[count] + 6, "on"))
					ts.ntlm = TRUE;
				else if (!strcmp(argv[count] + 6, "off"))
					ts.ntlm = FALSE;
				else
				{
					Usage(ts.stdo, &ts, TRUE);
					return 0;
				}
			}
#endif
			else if (!strncmp(argv[count] + 1, "line=", 5))
			{
				if (!strcmp(argv[count] + 6, "auto"))
					ts.line = LINE_AUTO;
				else if (!strcmp(argv[count] + 6, "cr"))
					ts.line = LINE_CR;
				else if (!strcmp(argv[count] + 6, "lf"))
					ts.line = LINE_LF;
				else if (!strcmp(argv[count] + 6, "crlf"))
					ts.line = LINE_CRLF;
				else
				{
					Usage(ts.stdo, &ts, TRUE);
					return 0;
				}
			}
#ifdef SUPPORT_JPNK
			else if (!strncmp(argv[count] + 1, "kanji=", 6))
			{
				for (ret = 0; js[ret].key != KANJI_NONE; ret++)
					if (!strcmp(argv[count] + 7, js[ret].name))
						break;
				if (js[ret].key != KANJI_NONE)
					ts.kanji = js[ret].key;
				else
				{
					Usage(ts.stdo, &ts, TRUE);
					return 0;
				}
			}
#endif
			else if (!strncmp(argv[count] + 1, "term=", 5))
			{
				if (strlen(argv[count] + 6) > 0)
					strcpy(term, argv[count] + 6);
			}
			else
			{
				Usage(ts.stdo, &ts, TRUE);
				return 0;
			}
		}
		else
		{
			switch (argn)
			{
			case 0:
				serv_name = argv[count];
				port_name = "23";	/* �W�� TELNET �|�[�g���g�p���� */
				break;
#ifdef SUPPORT_SERV
			case 1:
				port_name = argv[count];
				break;
#endif
			default:
				Usage(ts.stdo, &ts, TRUE);
				return 0;
			}
			argn++;
		}
	}

	if (serv_name == NULL)
	{
		Usage(ts.stdo, &ts, TRUE);
		return 0;
	}


	if (strlen(term) == 0)
	{
		memset(temp, 0x00, sizeof(temp));
		GetEnvironmentVariable("TERM", temp, sizeof(temp));
		if (strlen(temp) == 0)
		{
			ts.term = "kterm";
#ifdef SUPPORT_JPNK
			ts.ime = 1;
#endif
		}
		else
			ts.term = "vt100";
	}
	else
	{
		ts.term = term;
#ifdef SUPPORT_JPNK
		ts.ime = 1;
#endif
	}

	/* ���̓��[�h����͉\��!�ύX���� */
#ifdef SUPPORT_PIPE
	if (GetFileType(ts.stdi) != FILE_TYPE_PIPE)
#endif
	{
		ts.alto = CreateConsoleScreenBuffer(GENERIC_READ | GENERIC_WRITE,
			0, NULL, CONSOLE_TEXTMODE_BUFFER, NULL);

		GetConsoleMode(ts.stdi, &dwModeOld);
		dwMode = dwModeOld;
		dwMode &= ~ENABLE_LINE_INPUT;	/* ���C�����͎͂g��Ȃ� */
		dwMode &= ~ENABLE_ECHO_INPUT;	/* �G�R�[���͎͂g��Ȃ� */
		dwMode &= ~ENABLE_PROCESSED_INPUT;	/* CTRL-C���͎͂g��Ȃ� */
#ifdef SUPPORT_NAWS
		if (ts.naws)
			dwMode |= ENABLE_WINDOW_INPUT;
#endif
		dwMode |= ENABLE_MOUSE_INPUT;
		SetConsoleMode(ts.stdi, dwMode);

#ifdef SUPPORT_ICON
		hLibKernel32 = LoadLibrary("kernel32.dll");
		if (hLibKernel32)
		{
			if ((pfnGetConsoleWindow = (GETCONSOLEWINDOWPROC)
					GetProcAddress(hLibKernel32, "GetConsoleWindow")) != NULL)
				hWnd = (*pfnGetConsoleWindow) ();
			if (hWnd)
			{
				CHAR ExeName[MAX_PATH];
				memset(ExeName, 0x00, MAX_PATH);
				GetModuleFileName(NULL, ExeName, MAX_PATH);
				hIcon = ExtractIcon(NULL, ExeName, 0);
				if (hIcon)
				{
					hIconS = (HICON) SendMessage(hWnd, WM_SETICON,
						(WPARAM) ICON_SMALL, (LPARAM) hIcon);
					hIconB = (HICON) SendMessage(hWnd, WM_SETICON,
						(WPARAM) ICON_BIG, (LPARAM) hIcon);
				}
			}
		}
#endif
		if (GetConsoleTitle(title, sizeof(title)))
		{
#ifdef SUPPORT_SERV
			if (strcmp(serv_name, "-"))
#endif
			{
				strcpy(temp, "sTelNet - ");
				if (strlen(serv_name) > 70)
				{
					strncat(temp, serv_name, 70);
					strcat(temp, "...");
				}
				else
					strcat(temp, serv_name);
			}
#ifdef SUPPORT_SERV
			else
			{
				strcpy(temp, "sTelNet - Server");
			}
#endif
			SetConsoleTitle(temp);
		}
		else
			memset(title, 0x00, sizeof(title));

	}

	/* winsock �O���������� */
#ifdef SUPPORT_WSK2
	wVerReq = MAKEWORD(2, 0);
#else
	wVerReq = MAKEWORD(1, 1);
#endif
	WSAStartup(wVerReq, &wsaData);

#ifdef SUPPORT_SERV
	if (strcmp(serv_name, "-"))
#endif
	{
		/* �\�P�b�g���쐬���� */
		ts.sock = socket(AF_INET, SOCK_STREAM, 0);
		if (ts.sock == INVALID_SOCKET)
		{
#ifdef __GNUC__
			strcpy(temp, "�\\�P�b�g���m�ۂł��܂���\n");
#else
			strcpy(temp, "�\�P�b�g���m�ۂł��܂���\n");
#endif
			WriteFile(ts.stdo, temp, strlen(temp), &ret, NULL);
			goto ErrHandle;
		}

		/* �z�X�g�G���g�����擾���� */
		shost = gethostbyname(serv_name);
		if (shost == NULL)
		{
			closesocket(ts.sock);
			strcpy(temp, "�z�X�g����������܂���: ");
			strcat(temp, serv_name);
			strcat(temp, "\n");
			WriteFile(ts.stdo, temp, strlen(temp), &ret, NULL);
			goto ErrHandle;
		}

		/* �|�[�g���擾���� */
		ts.serv_port = (USHORT) atoi(port_name);
		nport = htons(ts.serv_port);
		if (nport == 0)
		{
			/* �|�[�g������������ */
			sserv = getservbyname(port_name, NULL);
			if (sserv == NULL)
			{
				closesocket(ts.sock);
				strcpy(temp, "�|�[�g����������܂���: ");
				strcat(temp, serv_name);
				strcat(temp, "\n");
				WriteFile(ts.stdo, temp, strlen(temp), &ret, NULL);
				goto ErrHandle;
			}
			nport = sserv->s_port;
			ts.serv_port = ntohs(nport);
		}
		memset((char *)&server, 0x00, sizeof(server));
		server.sin_family = AF_INET;
		server.sin_port = nport;
		memmove((char *)&server.sin_addr, shost->h_addr, shost->h_length);

		/* �\�P�b�g��ڑ����� */
		if (connect(ts.sock, (LPSOCKADDR) & server, sizeof(server))
			== SOCKET_ERROR)
		{
			closesocket(ts.sock);
			strcpy(temp, "�ڑ��ł��܂���: ");
			strcat(temp, serv_name);
			strcat(temp, ":");
			strcat(temp, port_name);
			strcat(temp, "\n");
			WriteFile(ts.stdo, temp, strlen(temp), &ret, NULL);
			goto ErrHandle;
		}

		/* �u���C�N��L���ɂ��� */
		ret = TRUE;
		setsockopt(ts.sock, (int)SOL_SOCKET, SO_OOBINLINE, (char FAR *)&ret,
			sizeof(BOOL));

		/* ���M�X���b�h���N������ */
		hThread = CreateThread(NULL,
			0, SendThread, (void *)&ts, 0, &ThreadID);

		/* ��M�X���b�h���N������ */
		RecvThread((void *)&ts);
		CloseHandle(hThread);
	}
#ifdef SUPPORT_SERV
	else
	{
		ts.serv_port = (USHORT) atoi(port_name);

		/* ���M�X���b�h���N������ */
		hThread = CreateThread(NULL,
			0, SendThread, (void *)&ts, 0, &ThreadID);

		/* �ҋ@�X���b�h���N������ */
		LstnThread((void *)&ts);
		if (WaitForSingleObject(hThread, 0) == WAIT_TIMEOUT)
			TerminateThread(hThread, 0);
		CloseHandle(hThread);
	}
#endif

  ErrHandle:

#ifdef SUPPORT_PIPE
	if (GetFileType(ts.stdi) != FILE_TYPE_PIPE)
#endif
	{
		SetConsoleMode(ts.stdi, dwModeOld);

		if (strlen(title))
			SetConsoleTitle(title);

#ifdef SUPPORT_ICON
		if (hWnd && hIcon)
		{
			SendMessage(hWnd, WM_SETICON, (WPARAM) ICON_SMALL,
				(LPARAM) hIconS);
			SendMessage(hWnd, WM_SETICON, (WPARAM) ICON_BIG, (LPARAM) hIconB);
		}
#endif
	}

	if (ts.alto != ts.stdo)
		CloseHandle(ts.alto);

	/* winsock �㏈�������� */
	WSACleanup();

	return GetLastError();
}
