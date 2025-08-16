#include <windows.h>
#include <winevt.h>
#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>
#include <filesystem>
#include <vector>
#include <regex>

#pragma comment(lib, "wevtapi.lib")

namespace fs = std::filesystem;

std::wstring ToLower(const std::wstring &s) {
    std::wstring out = s;
    std::transform(out.begin(), out.end(), out.begin(), ::towlower);
    return out;
}

void SearchServicesInLog(const std::wstring &channelPath, const std::wstring &target, std::wofstream &outfile, const std::string &format, bool useRegex) {
    std::wregex pattern;
    if (useRegex) {
        try {
            pattern = std::wregex(target, std::regex_constants::icase);
        } catch (const std::regex_error&) {
            std::wcerr << L"[!] Invalid regex pattern: " << target << std::endl;
            return;
        }
    }

    DWORD flags = EvtQueryReverseDirection | EvtQueryTolerateQueryErrors;
    if (channelPath.size() > 5 && ToLower(channelPath).rfind(L".evtx") == channelPath.size() - 5) {
        flags |= EvtQueryFilePath;
    }

    EVT_HANDLE hQuery = EvtQuery(NULL, channelPath.c_str(), NULL, flags);
    if (!hQuery) {
        DWORD err = GetLastError();
        if (err != ERROR_NOT_SUPPORTED) {
            std::wcerr << L"[!] Failed to open log: " << channelPath << L" Error: " << err << std::endl;
        }
        return;
    }

    EVT_HANDLE events[10];
    DWORD returned = 0;

    while (EvtNext(hQuery, 10, events, INFINITE, 0, &returned)) {
        for (DWORD i = 0; i < returned; i++) {
            DWORD bufferSize = 0, bufferUsed = 0, propertyCount = 0;
            EvtRender(NULL, events[i], EvtRenderEventXml, 0, NULL, &bufferUsed, &propertyCount);

            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                bufferSize = bufferUsed;
                WCHAR* buffer = new WCHAR[bufferSize / sizeof(WCHAR)];

                if (EvtRender(NULL, events[i], EvtRenderEventXml, bufferSize, buffer, &bufferUsed, &propertyCount)) {
                    std::wstring xml = ToLower(buffer);
                    bool matched = false;

                    if (useRegex) {
                        matched = std::regex_search(xml, pattern);
                    } else {
                        matched = xml.find(target) != std::wstring::npos;
                    }

                    if (matched) {
                        std::wstring header = L"[" + channelPath + L"]\n";
                        if (format == "xml" || format == "txt") {
                            outfile << header << buffer << L"\n";
                        } else if (format == "csv") {
                            std::wstring line = L"\"" + channelPath + L"\",\"" + buffer + L"\"\n";
                            outfile << line;
                        } else if (format == "json") {
                            std::wstring jsonEntry = L"{\"log\":\"" + channelPath + L"\",\"event\":\"" + buffer + L"\"}\n";
                            outfile << jsonEntry;
                        }
                    }
                }

                delete[] buffer;
            }

            EvtClose(events[i]);
        }
    }

    EvtClose(hQuery);
}

void ScanLiveLogs(const std::wstring &target, std::wofstream &outfile, const std::string &format, bool useRegex) {
    EVT_HANDLE hEnum = EvtOpenChannelEnum(NULL, 0);
    if (!hEnum) {
        std::wcerr << L"[!] EvtOpenChannelEnum failed: " << GetLastError() << std::endl;
        return;
    }

    WCHAR buf[512];
    DWORD bufSize = sizeof(buf);
    DWORD used = 0;

    while (EvtNextChannelPath(hEnum, bufSize / sizeof(WCHAR), buf, &used)) {
        SearchServicesInLog(buf, target, outfile, format, useRegex);
    }

    DWORD err = GetLastError();
    if (err != ERROR_NO_MORE_ITEMS) {
        std::wcerr << L"[!] EvtNextChannelPath failed: " << err << std::endl;
    }

    EvtClose(hEnum);
}

void ScanEvtxDirectory(const std::wstring &directory, const std::wstring &target, std::wofstream &outfile, const std::string &format, bool useRegex) {
    for (const auto &entry : fs::directory_iterator(directory)) {
        if (entry.path().extension() == L".evtx") {
            std::wcout << L"[*] Scanning file: " << entry.path() << std::endl;
            SearchServicesInLog(entry.path().wstring(), target, outfile, format, useRegex);
        }
    }
}

void PrintHelp() {
    std::wcout << L"Usage:\n"
               << L"  WinLogHunt.exe -i <keyword> [--live | -d <directory>] [-o <outputfile>] [-f <format>] [--regex] [-h]\n\n"
               << L"Options:\n"
               << L"  -h              : Show this help message\n"
               << L"  -i keyword      : Search keyword (service name) [REQUIRED]\n"
               
               << L"  -d directory    : Scan .evtx files from specified directory\n"
               << L"  -o outputfile   : Output file (default: results.xml)\n"
               << L"  -f format       : Output format: xml, json, csv, txt (default: xml)\n"
               << L"  --regex         : Treat keyword as a regex pattern\n"
               << L"  --live          : Scan live Windows event logs\n\n"
               
               << L"Notes:\n"
               << L"  Either --live or -d <directory> must be specified.\n"
               << L"  -i <keyword> is required to perform a search.\n";
}

int wmain(int argc, wchar_t* argv[]) {
    std::wstring target;
    std::wstring outputPath = L"results.xml";
    std::string format = "xml";
    std::wstring directory;
    bool live = false;
    bool useRegex = false;

    for (int i = 1; i < argc; i++) {
        std::wstring arg = argv[i];
        if (arg == L"-i" && i + 1 < argc) {
            target = argv[++i];
        } else if (arg == L"-o" && i + 1 < argc) {
            outputPath = argv[++i];
        } else if (arg == L"-f" && i + 1 < argc) {
            std::wstring f = ToLower(argv[++i]);
            if (f == L"xml" || f == L"txt" || f == L"csv" || f == L"json") {
                format = std::string(f.begin(), f.end());
            } else {
                std::wcerr << L"[!] Invalid format. Using xml." << std::endl;
            }
        } else if (arg == L"-d" && i + 1 < argc) {
            directory = argv[++i];
        } else if (arg == L"--live") {
            live = true;
        } else if (arg == L"--regex") {
            useRegex = true;
        } else if (arg == L"-h") {
            PrintHelp();
            return 0;
        } else {
            std::wcerr << L"[!] Unknown argument: " << arg << std::endl;
            PrintHelp();
            return 1;
        }
    }

    if (target.empty()) {
        std::wcerr << L"[!] Must provide a search keyword using -i <keyword>" << std::endl;
        PrintHelp();
        return 1;
    }

    if (!live && directory.empty()) {
        std::wcerr << L"[!] Must provide --live or -d <directory>" << std::endl;
        return 1;
    }

    std::wofstream outfile(outputPath);
    if (!outfile.is_open()) {
        std::wcerr << L"[!] Failed to open " << outputPath << L" for writing" << std::endl;
        return 1;
    }

    if (live) {
        ScanLiveLogs(target, outfile, format, useRegex);
    }

    if (!directory.empty()) {
        if (fs::exists(directory) && fs::is_directory(directory)) {
            ScanEvtxDirectory(directory, target, outfile, format, useRegex);
        } else {
            std::wcerr << L"[!] Directory does not exist: " << directory << std::endl;
        }
    }

    outfile.close();
    std::wcout << L"Results saved to " << outputPath << std::endl;
    return 0;
}
