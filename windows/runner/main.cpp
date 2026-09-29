#include <flutter/dart_project.h>
#include <flutter/flutter_view_controller.h>
#include <windows.h>

#include "flutter_window.h"
#include "utils.h"

namespace {

// 让本进程派生的子进程（hashcat / python）随本进程一起消失。
//
// 背景：hashcat 一旦启动就会把 GPU 吃满并长时间运行。用户直接关窗口时，
// Dart 隔离区被销毁，但 Process.start 出来的 hashcat.exe 是独立的 Windows
// 进程，不会跟着走——它会变成孤儿继续满载跑，表现为「应用关了，显卡占用
// 还是满的，而且半天退不出来」。
//
// 这里用 Job Object 的 KILL_ON_JOB_CLOSE 兜底：把本进程放进一个 job，
// Windows 默认会让本进程创建的每个子进程都加入同一个 job（Dart 的
// CreateProcess 不设 CREATE_BREAKAWAY_FROM_JOB）。当本进程退出、系统关闭
// job 句柄时，job 内所有进程被强制终止。这样即使 Dart 侧来不及清理、
// 甚至进程被任务管理器强杀，hashcat 也会立刻消失。
HANDLE g_kill_children_job = nullptr;

void AttachKillOnCloseJob() {
  HANDLE job = ::CreateJobObjectW(nullptr, nullptr);
  if (job == nullptr) return;

  JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = {};
  info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (!::SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info,
                                 sizeof(info))) {
    ::CloseHandle(job);
    return;
  }

  // Windows 8 以上支持嵌套 job；若当前进程已被别的 job 收编且系统不支持
  // 嵌套，这一步会失败——那就退化成「只靠 Dart 侧主动清理」，不影响运行。
  if (!::AssignProcessToJobObject(job, ::GetCurrentProcess())) {
    ::CloseHandle(job);
    return;
  }

  // 故意不关闭句柄：KILL_ON_JOB_CLOSE 的语义是「最后一个句柄关闭时终止」，
  // 进程退出时由系统关闭它，正好触发清理。
  g_kill_children_job = job;
}

}  // namespace

int APIENTRY wWinMain(_In_ HINSTANCE instance, _In_opt_ HINSTANCE prev,
                      _In_ wchar_t *command_line, _In_ int show_command) {
  AttachKillOnCloseJob();

  // Attach to console when present (e.g., 'flutter run') or create a
  // new console when running with a debugger.
  if (!::AttachConsole(ATTACH_PARENT_PROCESS) && ::IsDebuggerPresent()) {
    CreateAndAttachConsole();
  }

  // Initialize COM, so that it is available for use in the library and/or
  // plugins.
  ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

  flutter::DartProject project(L"data");

  std::vector<std::string> command_line_arguments =
      GetCommandLineArguments();

  project.set_dart_entrypoint_arguments(std::move(command_line_arguments));

  FlutterWindow window(project);
  Win32Window::Point origin(10, 10);
  Win32Window::Size size(1280, 720);
  if (!window.Create(L"hashcat_gui", origin, size)) {
    return EXIT_FAILURE;
  }
  window.SetQuitOnClose(true);

  ::MSG msg;
  while (::GetMessage(&msg, nullptr, 0, 0)) {
    ::TranslateMessage(&msg);
    ::DispatchMessage(&msg);
  }

  ::CoUninitialize();
  return EXIT_SUCCESS;
}
