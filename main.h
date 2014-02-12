#ifndef _MAIN_H_
#define _MAIN_H_

//
// Includes
//

#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#include <windows.h>
#include <Windowsx.h>
#include <tchar.h>
#include <Strsafe.h>

#include <http.h>
#pragma comment(lib, "httpapi.lib")

#include <iphlpapi.h>
#pragma comment(lib, "IPHLPAPI.lib")

#include <Commctrl.h>
#pragma comment(lib,"Comctl32.lib")

#include <Shlwapi.h>
#pragma comment(lib,"Shlwapi.lib")

#include "resource.h"
#include "./sqlite/sqlite3.h"

//
// Defines
//

#define ID_FLIPPED_TO_TRAY 1234
#define WM_FLIPPED_TO_TRAY (WM_APP + ID_FLIPPED_TO_TRAY)

#define STATIC_URL TEXT("http://localhost:8888/") // URL по которому будет открываться web-интерфейс
#define SLEEP_TIME 5000 // пауза в милисекундах между замерами трафика



//
// Macros.
//
#define INITIALIZE_HTTP_RESPONSE( resp, status, reason ) \
	do \
{ \
	RtlZeroMemory( (resp), sizeof(*(resp)) ); \
	(resp)->StatusCode = (status); \
	(resp)->pReason = (reason); \
	(resp)->ReasonLength = (USHORT) strlen(reason); \
} while (FALSE)

#define IS_HEADER(pRequest, HeaderId) pRequest->Headers.KnownHeaders[(HeaderId)].RawValueLength
#define GET_HEADER(pRequest, HeaderId) pRequest->Headers.KnownHeaders[(HeaderId)].pRawValue

#define ADD_KNOWN_HEADER(Response, HeaderId, RawValue) \
	do \
{ \
	(Response).Headers.KnownHeaders[(HeaderId)].pRawValue = \
	(RawValue);\
	(Response).Headers.KnownHeaders[(HeaderId)].RawValueLength = \
	(USHORT) strlen(RawValue); \
} while(FALSE)

#define ALLOC_MEM(cb) HeapAlloc(GetProcessHeap(), 0, (cb))
#define FREE_MEM(ptr) HeapFree(GetProcessHeap(), 0, (ptr))

//
// Struct.
//

typedef struct OPTIONS {
	NET_LUID InterfaceLuid;
	ULONG64 InOctets;
} Options;

//
// Globals.
//

NOTIFYICONDATA g_nid;
HWND g_hWnd;
HINSTANCE g_hInstance;
HMENU g_hMenu;
BOOL g_ThreadIsWork;
BOOL g_HTTPIsWork;
HANDLE g_hThread;
HANDLE g_hTimerQTimer;
Options options;
SOCKET sServerListen;
sqlite3 *db;

// 
// Functions.
//

/* Interface */
int WINAPI _tWinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,PTSTR lpCmdLine,int nShowCmd);
LRESULT CALLBACK GarikWinProc(HWND hWnd,UINT Message, UINT wParam, LONG lParam);
LRESULT CALLBACK SettingsProc(HWND hwndDlg,UINT Message, UINT wParam, LONG lParam);

/* Interface helper 
**
** Показывает всплывающие окно с инфрормацией в трее
** возвращает результат работы функции Shell_NotifyIcon
*/
BOOL showBalloon(const TCHAR *szInfoTitle, const TCHAR *szInfo);

/*
** Показывает форматированную подсказку в трее
** total - количество полученный БАЙТ
** возвращает результат работы функции Shell_NotifyIcon
*/
BOOL changeTipSize(ULONG64 total);

/*
** Сохраняет/получает настройки программы из реестра
*/
#define OPTIONS_SET TRUE
#define OPTIONS_GET FALSE
#define OPTIONS_NEW -1

int regOptions(OPTIONS * options,BOOL action);

/* Time and timer functions */
inline DWORD SystemTimeToMilliseconds(SYSTEMTIME *st);
DWORD getStartTime(); // возвращает количество милисекунд до 09:00
DWORD getStopTime(); // возвращает количество милисекунд до 01:00

VOID WINAPI workTimeout(PVOID pvContext, BOOLEAN fTimeout); // функция таймера, запускает или останавливает сбор данных

void StopWork();
void StartWork();

/*
** Поток получения информации от адаптера
** получает количество входящих октетов, сохраняет в БД, обновляет статус в трее
*/
DWORD WINAPI DoGetNetworkStatic(LPVOID lpParam);

/* HTTP functions */

/*
** Поток HTTP сервера
** получает и обрабатывает GET и POST запросы
** на GET запрос возвращает HTML страницу с JS кодом, зашитую в ресурсы
** на POST возвращает JSON ответ, формирует ответ из БД для заданного периода...
*/
DWORD WINAPI DoReceiveRequests(
	IN HANDLE hReqQueue
	);

DWORD SendHttpResponse(
	IN HANDLE hReqQueue,
	IN PHTTP_REQUEST pRequest,
	IN USHORT StatusCode,
	IN PSTR pReason,
	IN PCHAR pEntityBuffer,
	IN PLARGE_INTEGER pEntryBufferLength
	);

DWORD
	SendHttpPostResponse(
	IN HANDLE hReqQueue,
	IN PHTTP_REQUEST pRequest
	);

/*
** Формирует строку HTTP заголовка Last-Modified
** на основе timestamp из PE заголовка (время компиляции файла)
*/
int GetLastModifiedTime(const LPSTR pszDest, size_t cbDest);
DWORD getTimeStamp();

#endif /* !defined(_MAIN_H_) */