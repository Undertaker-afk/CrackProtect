#include <windows.h>
#include <string>

static HWND g_ProfileEdit = nullptr;

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM) {
    switch (uMsg) {
        case WM_CREATE: {
            CreateWindow("STATIC", "IronLock Configuration", WS_CHILD | WS_VISIBLE, 10, 10, 200, 20, hwnd, NULL, NULL, NULL);
            CreateWindow("STATIC", "Profile (json/toml/yaml):", WS_CHILD | WS_VISIBLE, 20, 40, 160, 20, hwnd, NULL, NULL, NULL);
            g_ProfileEdit = CreateWindow("EDIT", "profiles/safe-default.toml", WS_CHILD | WS_VISIBLE | WS_BORDER, 180, 40, 180, 20, hwnd, (HMENU)120, NULL, NULL);
            CreateWindow("BUTTON", "Export Report", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 20, 75, 200, 20, hwnd, (HMENU)130, NULL, NULL);
            CreateWindow("BUTTON", "PROTECT BINARY", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 20, 170, 150, 30, hwnd, (HMENU)201, NULL, NULL);
            CheckDlgButton(hwnd, 130, BST_CHECKED);
            break;
        }
        case WM_COMMAND: {
            if (LOWORD(wParam) == 201) {
                char profilePath[260] = {0};
                GetWindowTextA(g_ProfileEdit, profilePath, sizeof(profilePath));
                SetEnvironmentVariableA("IRONLOCK_PROFILE", profilePath);
                const bool report = IsDlgButtonChecked(hwnd, 130) == BST_CHECKED;
                std::string msg = std::string("Protection engine using profile:\n") + profilePath + (report ? "\nReport: enabled" : "\nReport: disabled");
                MessageBoxA(hwnd, msg.c_str(), "IronLock", MB_OK);
            }
            break;
        }
        case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, 0);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nShowCmd) {
    const char CLASS_NAME[] = "IronLockGUIClass";
    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClass(&wc);
    HWND hwnd = CreateWindowEx(WS_EX_ACCEPTFILES, CLASS_NAME, "IronLock GUI v1.2", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 420, 280, NULL, NULL, hInstance, NULL);
    if (hwnd == NULL) return 0;
    ShowWindow(hwnd, nShowCmd);
    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}
