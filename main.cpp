#include "main.h"

// 
// Interface 
//

int WINAPI _tWinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,PTSTR lpCmdLine,int nShowCmd)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	WSADATA ws;
	ULONG retCode;
	HANDLE hReqQueue = NULL;
	int UrlAdded = 0;
	HTTPAPI_VERSION HttpApiVersion = HTTPAPI_VERSION_1;
	DWORD dwThread;
	WNDCLASS WndClass={ sizeof(WndClass) };

	g_hInstance = hInstance;

	retCode = WSAStartup(0x202, &ws);
	if (NO_ERROR != retCode)
		return retCode;

	retCode = HttpInitialize(HttpApiVersion,HTTP_INITIALIZE_SERVER,NULL);

	if (NO_ERROR != retCode)
		return retCode;

	retCode = HttpCreateHttpHandle(&hReqQueue,0);
	if (NO_ERROR != retCode)
		goto CleanUp;

	retCode = HttpAddUrl(hReqQueue,STATIC_URL,NULL);
	if (NO_ERROR != retCode)
		goto CleanUp;

	char db_name[8] = {0x62, 0x61, 0x73, 0x65, 0x2E, 0x64, 0x62, 0x00};
	db = NULL;
	retCode = sqlite3_open(db_name, &db);
	if(SQLITE_OK != retCode)
		goto CleanUp;

	ZeroMemory(&options,sizeof(options));
	retCode = regOptions(&options,OPTIONS_GET);
	switch(retCode) 
	{
	case OPTIONS_NEW:
		{
			DialogBoxParam(hInstance,MAKEINTRESOURCE(IDD_SETTINGS),NULL,(DLGPROC)&SettingsProc,(LPARAM)&options);
			char create_sql[164] = {
				0x43, 0x52, 0x45, 0x41, 0x54, 0x45, 0x20, 0x54, 0x41, 0x42, 0x4C, 0x45, 0x20, 0x22, 0x63, 0x75, 
				0x72, 0x72, 0x65, 0x6E, 0x74, 0x22, 0x20, 0x28, 0x22, 0x69, 0x64, 0x22, 0x20, 0x49, 0x4E, 0x54, 
				0x45, 0x47, 0x45, 0x52, 0x20, 0x50, 0x52, 0x49, 0x4D, 0x41, 0x52, 0x59, 0x20, 0x4B, 0x45, 0x59, 
				0x20, 0x20, 0x41, 0x55, 0x54, 0x4F, 0x49, 0x4E, 0x43, 0x52, 0x45, 0x4D, 0x45, 0x4E, 0x54, 0x20, 
				0x20, 0x4E, 0x4F, 0x54, 0x20, 0x4E, 0x55, 0x4C, 0x4C, 0x20, 0x2C, 0x20, 0x22, 0x64, 0x61, 0x74, 
				0x65, 0x74, 0x69, 0x6D, 0x65, 0x22, 0x20, 0x44, 0x41, 0x54, 0x45, 0x54, 0x49, 0x4D, 0x45, 0x20, 
				0x4E, 0x4F, 0x54, 0x20, 0x4E, 0x55, 0x4C, 0x4C, 0x20, 0x20, 0x44, 0x45, 0x46, 0x41, 0x55, 0x4C, 
				0x54, 0x20, 0x43, 0x55, 0x52, 0x52, 0x45, 0x4E, 0x54, 0x5F, 0x54, 0x49, 0x4D, 0x45, 0x53, 0x54, 
				0x41, 0x4D, 0x50, 0x2C, 0x20, 0x22, 0x64, 0x6F, 0x77, 0x6E, 0x6C, 0x6F, 0x61, 0x64, 0x22, 0x20, 
				0x49, 0x4E, 0x54, 0x45, 0x47, 0x45, 0x52, 0x20, 0x4E, 0x4F, 0x54, 0x20, 0x4E, 0x55, 0x4C, 0x4C, 
				0x20, 0x29, 0x3B, 0x00
			};
			char *zErrMsg = 0;
			retCode = sqlite3_exec(db,create_sql,NULL,NULL,&zErrMsg);
			if(SQLITE_OK == retCode) break;
		}
	case FALSE:
		goto CleanUp;
	}

	g_HTTPIsWork = TRUE;
	HANDLE hHTTPThread = CreateThread(NULL,0,DoReceiveRequests,hReqQueue,NULL,&dwThread);
	CloseHandle(hHTTPThread);



	TCHAR szClassName[]=_TEXT("NetworkTraffic");
	WndClass.lpszClassName=szClassName;
	WndClass.lpfnWndProc=GarikWinProc;

	if(RegisterClass(&WndClass))
	{
		/*HWND hWnd=CreateWindowEx(WS_EX_LEFT| WS_EX_LTRREADING|WS_EX_PALETTEWINDOW,szClassName,NULL, WS_POPUPWINDOW|WS_THICKFRAME|WS_CLIPSIBLINGS|WS_CLIPCHILDREN,
		CW_USEDEFAULT,CW_USEDEFAULT,
		200,200,
		NULL,NULL,
		hInstance,NULL);*/

		HWND hWnd = CreateWindow(szClassName,NULL,NULL,0,0,0,0,NULL,NULL,hInstance,NULL);


		if(NULL != hWnd)
		{
			InitCommonControls();

			SecureZeroMemory(&g_nid,sizeof(g_nid));
			g_nid.cbSize=sizeof(g_nid);
			g_nid.hWnd = hWnd;
			g_nid.uID = ID_FLIPPED_TO_TRAY;
			g_nid.uCallbackMessage = WM_FLIPPED_TO_TRAY;
			g_nid.hIcon = LoadIcon(hInstance,MAKEINTRESOURCE(IDI_MAIN));
			g_nid.uFlags = NIF_ICON|NIF_MESSAGE|NIF_TIP|NIF_SHOWTIP|NIF_INFO;
			g_nid.uVersion = NOTIFYICON_VERSION_4;
			StringCchCopy(g_nid.szTip,ARRAYSIZE(g_nid.szTip),szClassName);

			if( Shell_NotifyIcon(NIM_ADD, &g_nid)) {

				MSG Msg;
				BOOL fGotMessage;

				ShowWindow(hWnd, SW_HIDE);

				while ((fGotMessage = GetMessage(&Msg, (HWND) NULL, 0, 0)) != 0 && fGotMessage != -1)
				{
					TranslateMessage(&Msg);
					DispatchMessage(&Msg);
				}

				Shell_NotifyIcon(NIM_DELETE, &g_nid);
			}
		}

	}

	regOptions(&options,OPTIONS_SET); // save 


CleanUp:
	if(db) sqlite3_close(db);

	g_HTTPIsWork = FALSE;

	HttpRemoveUrl(hReqQueue,STATIC_URL);

	if(hReqQueue)
		CloseHandle(hReqQueue);

	HttpTerminate(HTTP_INITIALIZE_SERVER, NULL);

	WSACleanup();

	return retCode;
}

LRESULT CALLBACK GarikWinProc(HWND hWnd,UINT Message, UINT wParam, LONG lParam)
{
	switch(Message)
	{
	case WM_CREATE:
		{
			g_hWnd = hWnd;
			g_hMenu = LoadMenu(g_hInstance,MAKEINTRESOURCE(POPUP_MENU));

			g_hTimerQTimer = g_hThread = NULL;

			StopWork();
			CreateTimerQueueTimer(&g_hTimerQTimer, NULL, workTimeout, NULL, getStartTime(), 0, 0);
			return 0;
		}
	case WM_COMMAND:
		{
			switch(LOWORD(wParam))
			{
			case IDM_SETTINGS:
				DialogBox(g_hInstance,MAKEINTRESOURCE(IDD_SETTINGS),hWnd,(DLGPROC)&SettingsProc);

				break;
			case IDM_EXIT:
				SendMessage(hWnd,WM_DESTROY,0,0);
				break;
			}
			return 0;

		}

	case WM_FLIPPED_TO_TRAY:
		{
			switch (LOWORD(lParam)) {

			case WM_LBUTTONUP:
				ShellExecute(0,_TEXT("open"),STATIC_URL,NULL,NULL,SW_SHOW); 
				break;

			case WM_RBUTTONUP:
				{
					HMENU hSubMenu = GetSubMenu(g_hMenu, 0);

					POINT point;
					GetCursorPos(&point);

					SetForegroundWindow(hWnd);
					TrackPopupMenu(hSubMenu,
						TPM_LEFTALIGN | TPM_RIGHTBUTTON,
						point.x, point.y,
						0,
						hWnd,
						NULL);
					PostMessage(hWnd, WM_NULL, 0, 0);
					break;
				}
			}

			return 0;
		}

		//case WM_NCHITTEST:
		// return HTBORDER;

	case WM_DESTROY:

		StopWork();
		if(NULL != g_hTimerQTimer) {
			DeleteTimerQueueTimer(NULL,g_hTimerQTimer,NULL);
		}

		DestroyMenu(g_hMenu);
		PostQuitMessage(0);
		return 0;
	}

	return DefWindowProc(hWnd,Message,wParam,lParam);
}

LRESULT CALLBACK SettingsProc(HWND hwndDlg,UINT Message, UINT wParam, LONG lParam)
{
	static NET_LUID * arrayLuid = NULL;

	switch (Message)
	{
	case WM_INITDIALOG:
		{
			HWND hLb = GetDlgItem(hwndDlg,IDC_LIST1);

			int selected = 0;

			PMIB_IF_TABLE2 pIfTable = NULL;
			if(NO_ERROR == GetIfTable2(&pIfTable))
			{
				arrayLuid = (NET_LUID *) malloc(sizeof(NET_LUID) * pIfTable->NumEntries);

				for(ULONG i=0; i < pIfTable->NumEntries; i++) {
					MIB_IF_ROW2 * pIfRow = (MIB_IF_ROW2 *) & pIfTable->Table[i];

					int index = ListBox_AddString(hLb,pIfRow->Description);
					arrayLuid[index] = pIfRow->InterfaceLuid;

					if(options.InterfaceLuid.Value == pIfRow->InterfaceLuid.Value)
						selected = index;
				}
				FreeMibTable(pIfTable);
			}

			ListBox_SetCurSel(hLb,selected);
			return TRUE;
		}
	case WM_COMMAND:
		{
			BOOL bChange=FALSE;
			switch (LOWORD(wParam))
			{
			case IDOK:
				{
					HWND hCb = GetDlgItem(hwndDlg,IDC_LIST1);
					int index = ListBox_GetCurSel(hCb);
					options.InterfaceLuid = arrayLuid[index];
					bChange = TRUE;
				}
			case IDCANCEL:
				if(NULL != arrayLuid) free(arrayLuid);

				EndDialog(hwndDlg, bChange);
				return TRUE;
			}
		}
	}
	return FALSE;
}

/* Interface helper */

BOOL showBalloon(const TCHAR *szInfoTitle, const TCHAR *szInfo)
{
	g_nid.uFlags = NIF_INFO | NIF_TIP;
	g_nid.dwInfoFlags = NIIF_INFO;

	StringCchCopy(g_nid.szInfoTitle,ARRAYSIZE(g_nid.szInfoTitle),szInfoTitle);
	StringCchCopy(g_nid.szTip,ARRAYSIZE(g_nid.szTip),szInfoTitle);
	StringCchCopy(g_nid.szInfo,ARRAYSIZE(g_nid.szInfo),szInfo);

	return Shell_NotifyIcon(NIM_MODIFY,&g_nid);
}

BOOL changeTipSize(ULONG64 total)
{
	TCHAR szSize[12];
	StrFormatByteSizeEx(total,SFBS_FLAGS_ROUND_TO_NEAREST_DISPLAYED_DIGIT,szSize,ARRAYSIZE(szSize));

	LONG64 procent = total * 100 / 26843545600;

	g_nid.uFlags = NIF_TIP;
	StringCchPrintf(g_nid.szTip,ARRAYSIZE(g_nid.szTip),_TEXT("Скачано %s - %d%% из 25 ГБ"),szSize,procent);

	return Shell_NotifyIcon(NIM_MODIFY,&g_nid);
}

int regOptions(OPTIONS * options,BOOL action)
{
	HKEY hKey;
	LONG lResult;
	DWORD MaxValueLen;

	lResult = RegCreateKeyEx(HKEY_CURRENT_USER, TEXT("Software\\Garik\\NetworkTraffic"),0, NULL, REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS, NULL, &hKey, &MaxValueLen);

	if ( ERROR_SUCCESS == lResult )
	{
		if(REG_CREATED_NEW_KEY == MaxValueLen) {
			options->InOctets = 0;
			SecureZeroMemory((PVOID)&options->InterfaceLuid,sizeof(options->InterfaceLuid));
			return OPTIONS_NEW;
		}

		switch(action)
		{
		case OPTIONS_SET:
			MaxValueLen=sizeof(options->InOctets);
			RegSetValueEx(hKey,_TEXT("InOctets"),0,REG_BINARY,(BYTE *)&options->InOctets,MaxValueLen);

			MaxValueLen=sizeof(options->InterfaceLuid);
			RegSetValueEx(hKey,_TEXT("InterfaceLuid"),0,REG_BINARY,(BYTE *)&options->InterfaceLuid,MaxValueLen);

			break;

		case OPTIONS_GET:
			MaxValueLen=sizeof(options->InOctets);
			RegQueryValueEx(hKey, _TEXT("InOctets"), NULL, NULL, (LPBYTE)&options->InOctets, &MaxValueLen);

			MaxValueLen=sizeof(options->InterfaceLuid);
			RegQueryValueEx(hKey, _TEXT("InterfaceLuid"), NULL, NULL, (LPBYTE)&options->InterfaceLuid, &MaxValueLen);

			break;
		default:
			return FALSE;
		}

		RegCloseKey(hKey);
		return TRUE;
	}

	return FALSE;
}

inline DWORD SystemTimeToMilliseconds(SYSTEMTIME *st) {
	return ( st->wHour * 60 * 60 * 1000 + st->wMinute * 60 * 1000 + st->wMilliseconds );
}

DWORD getStartTime()
{
	return 0;

	SYSTEMTIME st;
	DWORD dwCurrent,dwStart;

	GetLocalTime(&st);

	dwCurrent = SystemTimeToMilliseconds(&st);

	if(st.wHour >= 0 && st.wHour < 1)
		return 0;

	st.wHour = 9;
	st.wMinute = st.wSecond = st.wMilliseconds = 0;

	dwStart = SystemTimeToMilliseconds(&st);

	if(dwStart > dwCurrent)
		dwStart -= dwCurrent;
	else
		dwStart = 0;

	return dwStart;
}


DWORD getStopTime()
{
	return 60 * 1000;

	SYSTEMTIME st;
	DWORD dwCurrent,dwStart;

	GetLocalTime(&st);

	dwCurrent = SystemTimeToMilliseconds(&st);

	if(st.wHour >= 0 && st.wHour < 9)
		st.wHour = 1;
	else
		st.wHour = 24;

	st.wMinute = st.wSecond = st.wMilliseconds = 0;
	dwStart = SystemTimeToMilliseconds(&st);

	if(dwStart > dwCurrent)
		dwStart -= dwCurrent;
	else
		dwStart = 0;

	return dwStart;
}

void StopWork() {
	g_ThreadIsWork = FALSE;

	if(NULL != g_hThread) {
		WaitForSingleObject(g_hThread,INFINITE);
		CloseHandle(g_hThread); g_hThread = NULL;
	}
}

VOID WINAPI workTimeout(PVOID pvContext, BOOLEAN fTimeout) {

	DWORD dwDueTime;

	if(TRUE == g_ThreadIsWork) {
		StopWork();
		dwDueTime = getStartTime();
	} else {
		StartWork();
		dwDueTime = getStopTime();
	}

	DeleteTimerQueueTimer(NULL,g_hTimerQTimer,NULL);
	CreateTimerQueueTimer(&g_hTimerQTimer, NULL, workTimeout, NULL, dwDueTime, 0, 0);
}

DWORD WINAPI DoGetNetworkStatic(LPVOID lpParam) {

	ULONG64 TempInOctets,OldInOctets;
	TempInOctets = OldInOctets = 0;

	const char insert[48] = {
		0x49, 0x4E, 0x53, 0x45, 0x52, 0x54, 0x20, 0x49, 0x4E, 0x54, 0x4F, 0x20, 0x22, 0x63, 0x75, 0x72, 
		0x72, 0x65, 0x6E, 0x74, 0x22, 0x20, 0x28, 0x22, 0x64, 0x6F, 0x77, 0x6E, 0x6C, 0x6F, 0x61, 0x64, 
		0x22, 0x29, 0x20, 0x56, 0x41, 0x4C, 0x55, 0x45, 0x53, 0x20, 0x28, 0x3F, 0x31, 0x29, 0x3B, 0x00
	};
	sqlite3_stmt *pStmt = NULL;
	int rc = SQLITE_OK; 
	const char *zLeftover;



	MIB_IF_ROW2 IfRow;
	SecureZeroMemory((PVOID) &IfRow, sizeof(MIB_IF_ROW2) );
	IfRow.InterfaceLuid = options.InterfaceLuid;


	rc = sqlite3_prepare_v2(db, insert, sizeof(insert), &pStmt, &zLeftover);
	if(SQLITE_OK != rc) return rc;

	while(TRUE == g_ThreadIsWork) {
		if(NO_ERROR != GetIfEntry2(&IfRow))
			break;

		if (0 != OldInOctets)
			TempInOctets = IfRow.InOctets - OldInOctets;

		OldInOctets = IfRow.InOctets;
		options.InOctets += TempInOctets;

		if(TempInOctets > 0) {

			rc = sqlite3_bind_int64(pStmt, 1, options.InOctets);
			if(SQLITE_OK != rc) break;
			rc = sqlite3_step(pStmt);
			if(SQLITE_DONE != rc) break;


			changeTipSize(options.InOctets);
		}

		Sleep(SLEEP_TIME);
	}

	if(pStmt != NULL)
		rc = sqlite3_finalize(pStmt);

	return rc;
}

void StartWork() {
	g_ThreadIsWork = FALSE;


	DWORD dwThread;
	g_hThread = CreateThread(NULL,0,DoGetNetworkStatic,NULL,CREATE_SUSPENDED,&dwThread);
	if(NULL != g_hThread && SetThreadPriority(g_hThread, THREAD_PRIORITY_IDLE))
	{
		ResumeThread(g_hThread);
		g_ThreadIsWork = TRUE;
	}
}


DWORD getTimeStamp()
{
	char * memory = (char *)g_hInstance;
	IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)memory;
	if (DosHeader->e_magic == IMAGE_DOS_SIGNATURE) // проверим сигнатуру
	{
		IMAGE_NT_HEADERS * PeHeader=(IMAGE_NT_HEADERS *)(&memory[DosHeader->e_lfanew]);
		return PeHeader->FileHeader.TimeDateStamp;
	}
	return 0;
}

int GetLastModifiedTime(const LPSTR pszDest, size_t cbDest) // Sat, 01 Feb 2014 20:41:10 GMT
{
	FILETIME ft;
	SYSTEMTIME st;
	LONGLONG ll=Int32x32To64(getTimeStamp(), 10000000) + 116444736000000000;

	ft.dwLowDateTime = (DWORD)ll;
	ft.dwHighDateTime = ll >> 32;

	FileTimeToSystemTime(&ft,&st);

	TCHAR szDate[20];
	TCHAR szDateTime[30];
	GetDateFormatEx(TEXT("en-US"),NULL,&st,TEXT("ddd',' dd MMM yyyy"),szDate,20,NULL);
	StringCchPrintf(szDateTime,ARRAYSIZE(szDateTime),TEXT("%s %02d:%02d:%02d GMT"),szDate,st.wHour,st.wMinute,st.wSecond);

	return WideCharToMultiByte(CP_UTF8,0,szDateTime,ARRAYSIZE(szDateTime),pszDest,cbDest,NULL,NULL);
}

char second = 0;
static int WriteJSONTable(void *arg, int argc, char **argv, char **azColName){

	DWORD wr;
	char buff[0x200];
	int len = 0;

	if(second)
		buff[len++] = 0x2c;
	else 
		second = 1;




	buff[len++] = 0x7B; 
	for(int i=0;i<argc;i++)
	{
		len += sprintf_s(&buff[len],0x200 - len,"\"%s\":\"%s\"",azColName[i], argv[i] ? argv[i] : "");
		if(i+1 < argc) buff[len++] = 0x2c;
	}
	buff[len++] = 0x7D; 

	WriteFile((HANDLE)arg,buff,len,&wr,NULL);

	return 0;
}

HANDLE CreateJSONResponse()
{
	DWORD dwRetVal = 0;
	TCHAR lpTempPathBuffer[MAX_PATH],szTempFileName[MAX_PATH];
	HANDLE hTmpFile = INVALID_HANDLE_VALUE;

	dwRetVal = GetTempPath(MAX_PATH,          // length of the buffer
		lpTempPathBuffer); // buffer for path 
	if (dwRetVal > MAX_PATH || (dwRetVal == 0))
		return hTmpFile;

	if(0 == GetTempFileName(lpTempPathBuffer, // directory for tmp files
		TEXT("Nt"),     // temp file name prefix 
		0,                // create unique name 
		szTempFileName))
		return hTmpFile;


	hTmpFile = CreateFile(szTempFileName,GENERIC_WRITE|GENERIC_READ,FILE_SHARE_WRITE|FILE_SHARE_READ|FILE_SHARE_DELETE,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_TEMPORARY|FILE_FLAG_DELETE_ON_CLOSE,NULL);
	if(INVALID_HANDLE_VALUE == hTmpFile) return hTmpFile;

	TCHAR json[0x200];
	CHAR buff[0x200];


	// get Size
	TCHAR szSize[12];
	StrFormatByteSizeEx(options.InOctets,SFBS_FLAGS_ROUND_TO_NEAREST_DISPLAYED_DIGIT,szSize,ARRAYSIZE(szSize));

	StringCchPrintf(json,ARRAYSIZE(json),_TEXT("{\"current\":\"%s\",\"table\":["),szSize);

	int bufflen = WideCharToMultiByte(CP_UTF8,0,json,-1,buff,sizeof(buff)*sizeof(CHAR),NULL,NULL) - 1;
	WriteFile(hTmpFile,buff,bufflen,&dwRetVal,NULL); 

	char *zErrMsg = 0;
	char sql[40] = {
		0x53, 0x45, 0x4C, 0x45, 0x43, 0x54, 0x20, 0x64, 0x61, 0x74, 0x65, 0x74, 0x69, 0x6D, 0x65, 0x2C, 
		0x64, 0x6F, 0x77, 0x6E, 0x6C, 0x6F, 0x61, 0x64, 0x20, 0x46, 0x52, 0x4F, 0x4D, 0x20, 0x60, 0x63, 
		0x75, 0x72, 0x72, 0x65, 0x6E, 0x74, 0x60, 0x20
	}; // SELECT datetime,download FROM `current` 

	sqlite3_exec(db,sql,WriteJSONTable,hTmpFile,&zErrMsg);

	buff[0] = 0x5D; buff[1] = 0x7D; // ]}
	WriteFile(hTmpFile,buff,2,&dwRetVal,NULL); 

	return hTmpFile;
}


BYTE * GetMainIconResourse(DWORD *dwSize)
{
	BYTE * buff = NULL;
	*dwSize = 0;

	// TODO: костыль, иконка в ресурсах коцаная...
	BYTE data[22] = {
		0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0xA8, 0x0E, 
		0x00, 0x00, 0x16, 0x00, 0x00, 0x00
	};

	HRSRC hResource = FindResource(g_hInstance, MAKEINTRESOURCE(IDI_MAIN), MAKEINTRESOURCE(RT_GROUP_ICON));
	if(NULL != hResource) 
	{
		HGLOBAL hMem = LoadResource(g_hInstance, hResource); 
		if(NULL != hMem) {
			LPVOID lpResource = (LPVOID) LockResource(hMem);
			int nID = LookupIconIdFromDirectoryEx((PBYTE) lpResource, TRUE, 16, 16, LR_DEFAULTCOLOR); 

			hResource = FindResource(g_hInstance, MAKEINTRESOURCE(nID), MAKEINTRESOURCE(RT_ICON));
			if(NULL != hResource) {
				HGLOBAL hMem2 = LoadResource(g_hInstance, hResource); 
				if(NULL != hMem2) {
					lpResource = LockResource(hMem2);

					*dwSize = SizeofResource(g_hInstance, hResource);
					buff = (BYTE *) malloc(*dwSize + sizeof(data)); // replace to HeapAlloc
					memcpy(buff,data,sizeof(data));
					memcpy(&buff[sizeof(data)],lpResource, *dwSize);

					//FreeResource(hMem2);
				}
			}

			//FreeResource(hMem);
		}

	}

	return buff;
}

/*******************************************************************++

Routine Description:
The function to receive a request. This function calls the
corresponding function to handle the response.

Arguments:
hReqQueue - Handle to the request queue

Return Value:
Success/Failure.

--*******************************************************************/
DWORD WINAPI DoReceiveRequests(IN HANDLE hReqQueue) {

	ULONG result = 0;
	HTTP_REQUEST_ID requestId;
	DWORD bytesRead;

	CHAR szLastTime[30];
	GetLastModifiedTime(szLastTime,sizeof(szLastTime)*sizeof(CHAR));

	ULONG RequestBufferLength = sizeof(HTTP_REQUEST) + 2048;
	PCHAR pRequestBuffer = (PCHAR) ALLOC_MEM( RequestBufferLength );

	HRSRC hRes = FindResource(g_hInstance, MAKEINTRESOURCE(IDR_HTML1), RT_HTML); 
	HGLOBAL hMem = LoadResource(g_hInstance, hRes);
	LPVOID lpHTML = LockResource(hMem);
	DWORD dwHTMLSize = SizeofResource(g_hInstance, hRes);
	BOOL fFreeMem = FALSE;

	if(NULL != pRequestBuffer)
	{
		PHTTP_REQUEST pRequest = (PHTTP_REQUEST)pRequestBuffer;

		HTTP_SET_NULL_ID( &requestId );

		while(TRUE == g_HTTPIsWork) {
			RtlZeroMemory(pRequest, RequestBufferLength);
			result = HttpReceiveHttpRequest(hReqQueue,requestId,0,pRequest,RequestBufferLength,&bytesRead,NULL);

			if(NO_ERROR == result)
			{
				HTTP_RESPONSE response;
				HTTP_DATA_CHUNK dataChunk;
				DWORD result;
				DWORD bytesSent;

				switch(pRequest->Verb)
				{
				case HttpVerbGET: 
					{
						if(IS_HEADER(pRequest,HttpHeaderIfModifiedSince) > 0
							&& 0 == StrCmpA(GET_HEADER(pRequest,HttpHeaderIfModifiedSince),szLastTime)) 
						{
							INITIALIZE_HTTP_RESPONSE(&response, 304, "Not Modified");
						} 
						else if (0 == StrCmp(pRequest->CookedUrl.pAbsPath,_T("/"))) 
						{

							INITIALIZE_HTTP_RESPONSE(&response, 200, "OK");

							ADD_KNOWN_HEADER(response, HttpHeaderContentType, "text/html");
							ADD_KNOWN_HEADER(response, HttpHeaderLastModified, szLastTime);

							dataChunk.DataChunkType = HttpDataChunkFromMemory;
							dataChunk.FromMemory.pBuffer = lpHTML;
							dataChunk.FromMemory.BufferLength = (ULONG) dwHTMLSize;

							response.EntityChunkCount = 1;
							response.pEntityChunks = &dataChunk;

						}
						else if (0 == StrCmp(pRequest->CookedUrl.pAbsPath,_T("/favicon.ico"))) 
						{
							dataChunk.DataChunkType = HttpDataChunkFromMemory;
							dataChunk.FromMemory.pBuffer = GetMainIconResourse(&dataChunk.FromMemory.BufferLength);
							if(NULL != dataChunk.FromMemory.pBuffer) {

								INITIALIZE_HTTP_RESPONSE(&response, 200, "OK");
								ADD_KNOWN_HEADER(response, HttpHeaderContentType, "image/x-icon");

								response.EntityChunkCount = 1;
								response.pEntityChunks = &dataChunk;

								fFreeMem = TRUE;

							}
							else 
							{
								INITIALIZE_HTTP_RESPONSE(&response, 500, "Internal Server Error");
								break;
							}



						}
						else
						{
							INITIALIZE_HTTP_RESPONSE(&response, 404, "Not Found");
						}

						break; 
					}

				case HttpVerbPOST:

					dataChunk.DataChunkType = HttpDataChunkFromFileHandle;

					second = 0;

					dataChunk.FromFileHandle.FileHandle = CreateJSONResponse();

					if(INVALID_HANDLE_VALUE == dataChunk.FromFileHandle.FileHandle)
					{
						INITIALIZE_HTTP_RESPONSE(&response, 500, "Internal Server Error");
						break;
					}


					HTTP_BYTE_RANGE byteRange;
					ULARGE_INTEGER i;

					i.QuadPart = HTTP_BYTE_RANGE_TO_EOF;
					byteRange.Length = i;

					i.QuadPart = 0;
					byteRange.StartingOffset = i;

					dataChunk.FromFileHandle.ByteRange = byteRange;

					INITIALIZE_HTTP_RESPONSE(&response, 200, "OK");
					ADD_KNOWN_HEADER(response, HttpHeaderContentType, "application/json");

					response.EntityChunkCount = 1;
					response.pEntityChunks = &dataChunk;

					break;
				default:
					INITIALIZE_HTTP_RESPONSE(&response, 503, "Not Implemented");
					break;
				}

				result = HttpSendHttpResponse(hReqQueue,pRequest->RequestId, 0, &response, NULL,&bytesSent,NULL,0,NULL,NULL);

				if(fFreeMem) {
					free(dataChunk.FromMemory.pBuffer);
				}



				if(result != NO_ERROR)
					break;

				HTTP_SET_NULL_ID( &requestId );
			}
			else if(ERROR_MORE_DATA == result)
			{
				requestId = pRequest->RequestId;

				RequestBufferLength = bytesRead;
				FREE_MEM( pRequestBuffer );
				pRequestBuffer = (PCHAR) ALLOC_MEM( RequestBufferLength );

				if (pRequestBuffer == NULL)
				{
					result = ERROR_NOT_ENOUGH_MEMORY;
					break;
				}

				pRequest = (PHTTP_REQUEST)pRequestBuffer;
			}

			else if(result == ERROR_CONNECTION_INVALID && !HTTP_IS_NULL_ID(&requestId))
				HTTP_SET_NULL_ID( &requestId );
			else
				break;

		} // while

		FREE_MEM( pRequestBuffer );
	}

	//FreeResource(hMem);


	return result;
}