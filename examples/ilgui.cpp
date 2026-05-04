#include <windows.h>
#include <commctrl.h>
#include <string>

// IronLock GUI Protector Skeleton (Win32)

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            CreateWindowEx(0, "STATIC", "Drag and Drop your .EXE here to protect it with IronLock",
                           WS_CHILD | WS_VISIBLE | SS_CENTER, 20, 20, 360, 40, hwnd, NULL, NULL, NULL);
            break;
        }
        case WM_DROPFILES: {
            HDROP hDrop = (HDROP)wParam;
            char filePath[MAX_PATH];
            DragQueryFile(hDrop, 0, filePath, MAX_PATH);

            MessageBox(hwnd, (std::string("Protecting: ") + filePath).c_str(), "IronLock GUI", MB_OK);
            // Call CLI protection logic here

            DragFinish(hDrop);
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

    HWND hwnd = CreateWindowEx(WS_EX_ACCEPTFILES, CLASS_NAME, "IronLock GUI Protector",
                               WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 400, 200,
                               NULL, NULL, hInstance, NULL);

    if (hwnd == NULL) return 0;

    ShowWindow(hwnd, nShowCmd);

    MSG msg = { };
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}
