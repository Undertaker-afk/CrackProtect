#include <windows.h>

#include <array>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {
constexpr int kProfileEditId = 120;
constexpr int kProjectEditId = 121;
constexpr int kDroppedListId = 122;
constexpr int kFunctionRuleListId = 123;
constexpr int kCoverageId = 130;
constexpr int kCompatId = 131;
constexpr int kPerfId = 132;
constexpr int kExportHtmlId = 133;
constexpr int kExportPdfId = 134;
constexpr int kExportJsonId = 135;
constexpr int kProtectBtnId = 201;
constexpr int kExportCmdBtnId = 202;

HWND g_ProfileEdit = nullptr;
HWND g_ProjectEdit = nullptr;
HWND g_DroppedList = nullptr;
HWND g_FunctionRuleList = nullptr;
std::vector<std::string> g_Binaries;

void AppendListLine(HWND listBox, const std::string& line) {
    SendMessageA(listBox, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(line.c_str()));
}

std::string GetWindowString(HWND control) {
    std::array<char, 512> buffer{};
    GetWindowTextA(control, buffer.data(), static_cast<int>(buffer.size()));
    return buffer.data();
}

std::string BoolToJson(bool value) {
    return value ? "true" : "false";
}

std::string BuildCommand(bool html, bool pdf, bool json, bool coverage, bool compat, bool perf) {
    std::ostringstream cmd;
    cmd << "ilprotect_cli --profile \"" << GetWindowString(g_ProfileEdit) << "\"";
    for (const auto& binary : g_Binaries) {
        cmd << " --input \"" << binary << "\"";
    }

    cmd << " --project \"" << GetWindowString(g_ProjectEdit) << "\"";
    cmd << (coverage ? " --report-coverage" : "");
    cmd << (compat ? " --report-compat" : "");
    cmd << (perf ? " --report-performance" : "");
    cmd << (html ? " --export-html" : "");
    cmd << (pdf ? " --export-pdf" : "");
    cmd << (json ? " --export-json" : "");
    cmd << " --diagnostics structured";
    return cmd.str();
}

void SaveProjectFile(bool html, bool pdf, bool json, bool coverage, bool compat, bool perf) {
    const std::string path = GetWindowString(g_ProjectEdit);
    std::ofstream out(path, std::ios::trunc);
    if (!out) {
        MessageBoxA(nullptr, "Failed to write project file.", "IronLock GUI", MB_ICONERROR);
        return;
    }

    out << "{\n";
    out << "  \"profile\": \"" << GetWindowString(g_ProfileEdit) << "\",\n";
    out << "  \"targets\": [\n";
    for (size_t i = 0; i < g_Binaries.size(); ++i) {
        out << "    \"" << g_Binaries[i] << "\"" << (i + 1 == g_Binaries.size() ? "\n" : ",\n");
    }
    out << "  ],\n";
    out << "  \"reports\": {\n";
    out << "    \"coverage\": " << BoolToJson(coverage) << ",\n";
    out << "    \"compatibility\": " << BoolToJson(compat) << ",\n";
    out << "    \"performance\": " << BoolToJson(perf) << "\n";
    out << "  },\n";
    out << "  \"exports\": {\n";
    out << "    \"html\": " << BoolToJson(html) << ",\n";
    out << "    \"pdf\": " << BoolToJson(pdf) << ",\n";
    out << "    \"json\": " << BoolToJson(json) << "\n";
    out << "  },\n";
    out << "  \"failureDiagnostics\": \"structured-with-hints\"\n";
    out << "}\n";
}

void PopulateDefaultRules() {
    SendMessageA(g_FunctionRuleList, LB_RESETCONTENT, 0, 0);
    AppendListLine(g_FunctionRuleList, "Auth::ValidateLicense -> virtualize, cff");
    AppendListLine(g_FunctionRuleList, "Net::RequestToken -> string-obfuscation");
    AppendListLine(g_FunctionRuleList, "Core::LoadSecrets -> vm + anti-dump");
}
}  // namespace

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            CreateWindow("STATIC", "IronLock Product Layer", WS_CHILD | WS_VISIBLE, 10, 8, 300, 20, hwnd, NULL, NULL, NULL);
            CreateWindow("STATIC", "Profile:", WS_CHILD | WS_VISIBLE, 20, 36, 80, 20, hwnd, NULL, NULL, NULL);
            g_ProfileEdit = CreateWindow("EDIT", "profiles/safe-default.toml", WS_CHILD | WS_VISIBLE | WS_BORDER, 110, 34, 300, 22, hwnd, (HMENU)kProfileEditId, NULL, NULL);
            CreateWindow("STATIC", "Project file:", WS_CHILD | WS_VISIBLE, 20, 66, 80, 20, hwnd, NULL, NULL, NULL);
            g_ProjectEdit = CreateWindow("EDIT", "project.ilproj.json", WS_CHILD | WS_VISIBLE | WS_BORDER, 110, 64, 300, 22, hwnd, (HMENU)kProjectEditId, NULL, NULL);
            CreateWindow("STATIC", "Drop binaries:", WS_CHILD | WS_VISIBLE, 20, 96, 120, 20, hwnd, NULL, NULL, NULL);
            g_DroppedList = CreateWindow("LISTBOX", "", WS_CHILD | WS_VISIBLE | WS_BORDER | LBS_NOTIFY, 20, 116, 390, 80, hwnd, (HMENU)kDroppedListId, NULL, NULL);
            CreateWindow("STATIC", "Per-function rules:", WS_CHILD | WS_VISIBLE, 20, 201, 120, 20, hwnd, NULL, NULL, NULL);
            g_FunctionRuleList = CreateWindow("LISTBOX", "", WS_CHILD | WS_VISIBLE | WS_BORDER, 20, 221, 390, 70, hwnd, (HMENU)kFunctionRuleListId, NULL, NULL);
            PopulateDefaultRules();

            CreateWindow("BUTTON", "Coverage report", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 430, 34, 190, 20, hwnd, (HMENU)kCoverageId, NULL, NULL);
            CreateWindow("BUTTON", "Compatibility report", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 430, 57, 190, 20, hwnd, (HMENU)kCompatId, NULL, NULL);
            CreateWindow("BUTTON", "Performance report", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 430, 80, 190, 20, hwnd, (HMENU)kPerfId, NULL, NULL);
            CreateWindow("BUTTON", "Export HTML", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 430, 116, 190, 20, hwnd, (HMENU)kExportHtmlId, NULL, NULL);
            CreateWindow("BUTTON", "Export PDF", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 430, 139, 190, 20, hwnd, (HMENU)kExportPdfId, NULL, NULL);
            CreateWindow("BUTTON", "Export JSON", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 430, 162, 190, 20, hwnd, (HMENU)kExportJsonId, NULL, NULL);
            CheckDlgButton(hwnd, kCoverageId, BST_CHECKED);
            CheckDlgButton(hwnd, kCompatId, BST_CHECKED);
            CheckDlgButton(hwnd, kPerfId, BST_CHECKED);
            CheckDlgButton(hwnd, kExportHtmlId, BST_CHECKED);
            CheckDlgButton(hwnd, kExportJsonId, BST_CHECKED);

            CreateWindow("BUTTON", "Protect + Save Project", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 430, 221, 190, 30, hwnd, (HMENU)kProtectBtnId, NULL, NULL);
            CreateWindow("BUTTON", "Copy CI Command", WS_CHILD | WS_VISIBLE, 430, 261, 190, 30, hwnd, (HMENU)kExportCmdBtnId, NULL, NULL);
            break;
        }
        case WM_DROPFILES: {
            HDROP drop = reinterpret_cast<HDROP>(wParam);
            const UINT count = DragQueryFileA(drop, 0xFFFFFFFF, NULL, 0);
            for (UINT i = 0; i < count; ++i) {
                std::array<char, MAX_PATH> path{};
                DragQueryFileA(drop, i, path.data(), static_cast<UINT>(path.size()));
                g_Binaries.emplace_back(path.data());
                AppendListLine(g_DroppedList, path.data());
            }
            DragFinish(drop);
            break;
        }
        case WM_COMMAND: {
            const bool coverage = IsDlgButtonChecked(hwnd, kCoverageId) == BST_CHECKED;
            const bool compat = IsDlgButtonChecked(hwnd, kCompatId) == BST_CHECKED;
            const bool perf = IsDlgButtonChecked(hwnd, kPerfId) == BST_CHECKED;
            const bool html = IsDlgButtonChecked(hwnd, kExportHtmlId) == BST_CHECKED;
            const bool pdf = IsDlgButtonChecked(hwnd, kExportPdfId) == BST_CHECKED;
            const bool json = IsDlgButtonChecked(hwnd, kExportJsonId) == BST_CHECKED;

            if (LOWORD(wParam) == kProtectBtnId) {
                SaveProjectFile(html, pdf, json, coverage, compat, perf);
                const std::string command = BuildCommand(html, pdf, json, coverage, compat, perf);
                std::string msg = "Project and preset saved.\n\nCI command:\n" + command +
                                  "\n\nFailure diagnostics are configured as structured-with-hints.";
                MessageBoxA(hwnd, msg.c_str(), "IronLock Product Layer", MB_OK);
            } else if (LOWORD(wParam) == kExportCmdBtnId) {
                const std::string command = BuildCommand(html, pdf, json, coverage, compat, perf);
                OpenClipboard(hwnd);
                EmptyClipboard();
                HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, command.size() + 1);
                if (memory) {
                    memcpy(GlobalLock(memory), command.c_str(), command.size() + 1);
                    GlobalUnlock(memory);
                    SetClipboardData(CF_TEXT, memory);
                }
                CloseClipboard();
                MessageBoxA(hwnd, "CI command copied to clipboard.", "IronLock Product Layer", MB_OK);
            }
            break;
        }
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nShowCmd) {
    const char CLASS_NAME[] = "IronLockGUIClass";
    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClass(&wc);

    HWND hwnd = CreateWindowEx(WS_EX_ACCEPTFILES, CLASS_NAME, "IronLock GUI Product Layer", WS_OVERLAPPEDWINDOW,
                               CW_USEDEFAULT, CW_USEDEFAULT, 660, 360, NULL, NULL, hInstance, NULL);
    if (hwnd == NULL) return 0;
    ShowWindow(hwnd, nShowCmd);

    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}
