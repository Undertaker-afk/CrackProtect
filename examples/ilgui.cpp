#include <windows.h>
#include <string>
#include <vector>

// IronLock GUI v1.1 - Feature Configuration Interface

struct FeatureConfig {
    bool antiDebug = true;
    bool antiVM = true;
    bool networkProtect = true;
    int inflationLevel = 0;
    int baitCount = 10;
};

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            CreateWindow("STATIC", "IronLock Configuration", WS_CHILD | WS_VISIBLE, 10, 10, 200, 20, hwnd, NULL, NULL, NULL);
            CreateWindow("BUTTON", "Enable Anti-Debug", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 20, 40, 200, 20, hwnd, (HMENU)101, NULL, NULL);
            CreateWindow("BUTTON", "Enable Anti-VM", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 20, 70, 200, 20, hwnd, (HMENU)102, NULL, NULL);
            CreateWindow("BUTTON", "Network Protection", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 20, 100, 200, 20, hwnd, (HMENU)103, NULL, NULL);

            CreateWindow("STATIC", "Bait Count:", WS_CHILD | WS_VISIBLE, 20, 130, 80, 20, hwnd, NULL, NULL, NULL);
            CreateWindow("EDIT", "20", WS_CHILD | WS_VISIBLE | WS_BORDER, 110, 130, 40, 20, hwnd, (HMENU)104, NULL, NULL);

            CreateWindow("BUTTON", "PROTECT BINARY", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 20, 170, 150, 30, hwnd, (HMENU)201, NULL, NULL);

            CheckDlgButton(hwnd, 101, BST_CHECKED);
            CheckDlgButton(hwnd, 102, BST_CHECKED);
            CheckDlgButton(hwnd, 103, BST_CHECKED);
            break;
        }
        case WM_COMMAND: {
            if (LOWORD(wParam) == 201) {
                MessageBox(hwnd, "Protection engine starting with selected features...", "IronLock", MB_OK);
            }
            break;
        }
        case WM_DESTROY: {
            PostQuitMessage(0);
            return 0;
        }
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    const char CLASS_NAME[] = "IronLockGUIClass";
    WNDCLASS wc = { };
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClass(&wc);
    HWND hwnd = CreateWindowEx(WS_EX_ACCEPTFILES, CLASS_NAME, "IronLock GUI v1.1", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 400, 300, NULL, NULL, hInstance, NULL);
    if (hwnd == NULL) return 0;
    ShowWindow(hwnd, nShowCmd);
    MSG msg = { };
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}
