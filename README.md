# Windows Event Log Extractor

A C++ tool for searching Windows Event Logs — both live system channels and offline `.evtx` files — for specific keywords (process names, service names, commands, etc.).  
Useful for incident response, threat hunting, and forensic analysis.

---

## Features

- **Live Log Scanning**: Enumerates all event log channels and searches their entries.
- **Offline Analysis**: Recursively scans directories for `.evtx` files and searches them.
- **Case-Insensitive Search**: Matches regardless of case.
- **Flexible Search Term**: Search any substring or use regex patterns with the `--regex` option.
- **Multiple Formats**: Supports `xml`, `txt`, `csv`, and `json`.

---

## Output Details

For every matched event, the tool provides:

* **Source** – The origin of the event, either a live log channel (e.g., `[Security]`) or the full path to an offline `.evtx` file.
* **Event Content** – The complete content of the event in the chosen output format (`xml`, `txt`, `csv`, or `json`), including all relevant details such as timestamps, EventID, provider, and associated parameters.

All results are displayed in the console as they are found and also written to the specified output file for later analysis.

---


---

## Prerequisites

- Windows 10 / Windows 11  
- Visual Studio 2019+ (C++ toolset) or MSVC command-line (cl)  
- `wevtapi.lib` (part of Windows SDK)  
- Administrator privileges recommended for scanning live logs (particularly Security or other protected channels)

---

## Build

```cmd
compile.bat
```

---

## Usage

**Search live logs for `services.exe`:**
```cmd
WinLogHunt.exe -i services.exe --live
```

**Search live logs using regex (e.g., any `exe` in `C:\Windows\System32`):**
```cmd
WinLogHunt.exe -i "C:\\Windows\\System32\\.*\.exe" --live --regex
```

**Scan offline logs:**
```cmd
WinLogHunt.exe -i powershell -d "D:\DiskImage\Windows\System32\winevt\logs"
```

**Output in JSON format:**
```cmd
WinLogHunt.exe -i cmd.exe --live -f json -o cmd_results.json
```

---

## Example output (snippet)

```
[*] Scanning file: "D:\...\Security.evtx"
[Security.evtx]
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System> ... </System>
  <EventData>
    <Data Name="ProcessName">C:\Windows\System32\services.exe</Data>
    ...
  </EventData>
</Event>

Results saved to results.xml
```

---

## Security considerations

- Event XML may contain sensitive information (usernames, hostnames, file paths).
- If running on production systems, get appropriate authorization and run in a controlled environment.
- Avoid exposing output files to untrusted parties.

---

## Contributing

Contributions, bug reports, and feature requests are welcome. Open an issue or submit a pull request with a clear description and test cases.

---

## License

This tool is provided as-is for educational, forensic, and research purposes. Use responsibly and in accordance with applicable laws and organizational policies.

---

