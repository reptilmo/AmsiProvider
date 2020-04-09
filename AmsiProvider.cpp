#include "stdafx.h"

#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <codecvt>

using namespace Microsoft::WRL;
constexpr auto kStringBufferSize = 512;

class SimpleLogFile final {
public:
	SimpleLogFile(const char* file_name) {
		log_file_.open(file_name, std::ios::out | std::ios::app);
	}
	SimpleLogFile() {
		log_file_.close();
	}
	void Put(const char* message) {
		log_file_ << message << L"\n";
	}
	void  Put(const std::string& message) {
		log_file_ << message << " " << "\n";
	}
	void Put(const char* message, uint64_t param) {
		log_file_ << message << " " << param << "\n";
	}
    void Put(const char* message, const char* param) {
		log_file_ << message << " " << param << "\n";
    }
	void Put(const char* message, const std::string& param) {
		log_file_ << message << " " << param << "\n";
	}
private:
	std::ofstream log_file_;
};


HMODULE g_currentModule;
SimpleLogFile myLog("C:\\TestAmsiProvider.log");

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        g_currentModule = module;
        DisableThreadLibraryCalls(module);
        myLog.Put("DLL Loaded");
        Module<InProc>::GetModule().Create();
        break;

    case DLL_PROCESS_DETACH:
        Module<InProc>::GetModule().Terminate();
		myLog.Put("DLL Unloaded");
        break;
    }

    return TRUE;
}

#pragma region COM server boilerplate
HRESULT WINAPI DllCanUnloadNow() {
	myLog.Put("DllCanUnloadNow");
    return Module<InProc>::GetModule().Terminate() ? S_OK : S_FALSE;
}

STDAPI DllGetClassObject(_In_ REFCLSID rclsid, _In_ REFIID riid, _Outptr_ LPVOID FAR* ppv) {
	myLog.Put("DllGetClassObject");
    return Module<InProc>::GetModule().GetClassObject(rclsid, riid, ppv);
}
#pragma endregion

class DECLSPEC_UUID("215D8A64-77F9-4F7B-A90C-2744820139B2") TestAmsiProvider
	: public RuntimeClass<RuntimeClassFlags<ClassicCom>, IAntimalwareProvider, FtmBase> {
public:
    IFACEMETHOD(Scan)(_In_ IAmsiStream* stream, _Out_ AMSI_RESULT* result) override;
    IFACEMETHOD_(void, CloseSession)(_In_ ULONGLONG session) override;
    IFACEMETHOD(DisplayName)(_Outptr_ LPWSTR* displayName) override;

private:
    // We assign each Scan request a unique number for logging purposes.
    LONG m_requestNumber = 0;
};

template<typename T>
T GetFixedSizeAttribute(_In_ IAmsiStream* stream, _In_ AMSI_ATTRIBUTE attribute)
{
    T result;

    ULONG actualSize;
    if (SUCCEEDED(stream->GetAttribute(attribute, sizeof(T), reinterpret_cast<unsigned char*>(&result), &actualSize)) &&
        actualSize == sizeof(T))
    {
        return result;
    }
	return T{};
}

std::string GetStringAttribute(_In_ IAmsiStream* stream, _In_ AMSI_ATTRIBUTE attribute) {

	ULONG alloc_size = 0;
	ULONG actual_size = 0;

	if (stream->GetAttribute(attribute, 0, nullptr, &alloc_size) == E_NOT_SUFFICIENT_BUFFER) {
		std::vector<wchar_t> buffer(alloc_size);

		if (SUCCEEDED(stream->GetAttribute(attribute, alloc_size, reinterpret_cast<PBYTE>(buffer.data()),
			&actual_size)) && actual_size <= alloc_size) {

			std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
			return converter.to_bytes(std::wstring(buffer.begin(), buffer.end()));

		}
    }

	return std::string("");
}

HRESULT TestAmsiProvider::Scan(_In_ IAmsiStream* stream, _Out_ AMSI_RESULT* result)
{
    LONG requestNumber = InterlockedIncrement(&m_requestNumber);
    myLog.Put("Scan Start", requestNumber);

    auto appName = GetStringAttribute(stream, AMSI_ATTRIBUTE_APP_NAME);
    myLog.Put("App Name: ", appName);
    auto contentName = GetStringAttribute(stream, AMSI_ATTRIBUTE_CONTENT_NAME);
    myLog.Put("Content Name: ", contentName);
    auto contentSize = GetFixedSizeAttribute<uint64_t>(stream, AMSI_ATTRIBUTE_CONTENT_SIZE);
    myLog.Put("Content Size: ", contentSize);
    auto session = GetFixedSizeAttribute<uint64_t>(stream, AMSI_ATTRIBUTE_SESSION);
    myLog.Put("Session: ", session);
    const auto contentAddress = GetFixedSizeAttribute<char*>(stream, AMSI_ATTRIBUTE_CONTENT_ADDRESS);
    myLog.Put("Content Provided: ", contentAddress ? "BUFFER" : "STREAM");

    if (contentAddress) {
		myLog.Put("BUFFER START");
		std::wstring wide_buffer(contentAddress, contentAddress + contentSize);

		std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
		myLog.Put(converter.to_bytes(wide_buffer));

		myLog.Put("BUFFER END");
	}
/*    else
    {
        // Provided as a stream. Read it stream a chunk at a time.
        BYTE cumulativeXor = 0;
        BYTE chunk[1024];
        ULONG readSize;
        for (ULONGLONG position = 0; position < contentSize; position += readSize)
        {
            HRESULT hr = stream->Read(position, sizeof(chunk), chunk, &readSize);
            if (SUCCEEDED(hr))
            {
                cumulativeXor ^= CalculateBufferXor(chunk, readSize);
                TraceLoggingWrite(g_traceLoggingProvider, "Read chunk",
                    TraceLoggingValue(requestNumber),
                    TraceLoggingValue(position),
                    TraceLoggingValue(readSize),
                    TraceLoggingValue(cumulativeXor));
            }
            else
            {
                TraceLoggingWrite(g_traceLoggingProvider, "Read failed",
                    TraceLoggingValue(requestNumber),
                    TraceLoggingValue(position),
                    TraceLoggingValue(hr));
                break;
            }
        }
    }*/
	
    myLog.Put("Scan End", requestNumber);

    // AMSI_RESULT_NOT_DETECTED means "We did not detect a problem but let other providers scan it, too."
    *result = AMSI_RESULT_NOT_DETECTED;
    return S_OK;
}

void TestAmsiProvider::CloseSession(_In_ ULONGLONG session)
{
    myLog.Put("Close session", session);
}

HRESULT TestAmsiProvider::DisplayName(_Outptr_ LPWSTR *displayName)
{
    *displayName = const_cast<LPWSTR>(L"Sample AMSI Provider");
    return S_OK;
}

CoCreatableClass(TestAmsiProvider);

#pragma region Install / uninstall

HRESULT SetKeyStringValue(_In_ HKEY key, _In_opt_ PCWSTR subkey, _In_opt_ PCWSTR valueName, _In_ PCWSTR stringValue)
{
    LONG status = RegSetKeyValue(key, subkey, valueName, REG_SZ, stringValue, (wcslen(stringValue) + 1) * sizeof(wchar_t));
    return HRESULT_FROM_WIN32(status);
}

STDAPI DllRegisterServer()
{
    wchar_t modulePath[MAX_PATH];
    if (GetModuleFileName(g_currentModule, modulePath, ARRAYSIZE(modulePath)) >= ARRAYSIZE(modulePath)) {
        myLog.Put("ERROR: GetModuleFileName");
        return E_UNEXPECTED;
    }

    // Create a standard COM registration for our CLSID.
    // The class must be registered as "Both" threading model
    // and support multithreaded access.
    wchar_t clsidString[40];
    if (StringFromGUID2(__uuidof(TestAmsiProvider), clsidString, ARRAYSIZE(clsidString)) == 0)
    {
        myLog.Put("ERROR: StringFromGUID2");
        return E_UNEXPECTED;
    }

    wchar_t keyPath[200];
    HRESULT hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Classes\\CLSID\\%ls", clsidString);
	if (FAILED(hr)) {
		myLog.Put("ERROR: 0");
		return hr;
	}

    hr = SetKeyStringValue(HKEY_LOCAL_MACHINE, keyPath, nullptr, L"TestAmsiProvider");
    if (FAILED(hr)) {
        myLog.Put("ERROR: 1");
        return hr;
    }

    hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Classes\\CLSID\\%ls\\InProcServer32", clsidString);
    if (FAILED(hr)) {
        myLog.Put("ERROR: 2");
        return hr;
    }

    hr = SetKeyStringValue(HKEY_LOCAL_MACHINE, keyPath, nullptr, modulePath);
    if (FAILED(hr)) {
        myLog.Put("ERROR: 3");
        return hr;
    }

    hr = SetKeyStringValue(HKEY_LOCAL_MACHINE, keyPath, L"ThreadingModel", L"Both");
    if (FAILED(hr)) {
        myLog.Put("ERROR: 4");
        return hr;
    }

    // Register this CLSID as an anti-malware provider.
    hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Microsoft\\AMSI\\Providers\\%ls", clsidString);
    if (FAILED(hr)) {
        myLog.Put("ERROR: 5");
        return hr;
    }

    hr = SetKeyStringValue(HKEY_LOCAL_MACHINE, keyPath, nullptr, L"TestAmsiProvider");
    if (FAILED(hr)) {
        myLog.Put("ERROR: 6");
        return hr;
    }

	myLog.Put("DllRegisterServer succeeded");

    return S_OK;
}

STDAPI DllUnregisterServer()
{
	myLog.Put("DllUnregisterServer");
    wchar_t clsidString[40];
    if (StringFromGUID2(__uuidof(TestAmsiProvider), clsidString, ARRAYSIZE(clsidString)) == 0) {
		myLog.Put("Unregister ERROR: StringFromGUID2");
        return E_UNEXPECTED;
    }

    // Unregister this CLSID as an anti-malware provider.
    wchar_t keyPath[200];
    HRESULT hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Microsoft\\AMSI\\Providers\\%ls", clsidString);
    if (FAILED(hr)) {
		myLog.Put("Unregister ERROR: 0");
        return hr;
    }
    LONG status = RegDeleteTree(HKEY_LOCAL_MACHINE, keyPath);
    if (status != NO_ERROR && status != ERROR_PATH_NOT_FOUND) return HRESULT_FROM_WIN32(status);

    // Unregister this CLSID as a COM server.
    hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Classes\\CLSID\\%ls", clsidString);
    if (FAILED(hr)) {
		myLog.Put("Unregister ERROR: 1");
        return hr;
    }
    status = RegDeleteTree(HKEY_LOCAL_MACHINE, keyPath);
    if (status != NO_ERROR && status != ERROR_PATH_NOT_FOUND) return HRESULT_FROM_WIN32(status);

    return S_OK;
}
#pragma endregion
