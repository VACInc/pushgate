"""Build the former PLAP-only mutant; unit.exe must reject it on Windows."""
from pathlib import Path
import shutil
import subprocess

root = Path(__file__).resolve().parents[1]
work = root / "build" / "oldcallback"
for directory in ("src", "tests"):
    (work / directory).mkdir(parents=True, exist_ok=True)
source = (root / "src" / "provider.cpp").read_text()
start = source.index("  // Connect is documented for PLAP.")
end = source.index("  std::lock_guard<std::mutex> lock(state);", start)
(work / "src" / "provider.cpp").write_text(source[:start] + source[end:])
shutil.copy2(root / "src" / "gate.h", work / "src" / "gate.h")
shutil.copy2(root / "src" / "scope.h", work / "src" / "scope.h")
shutil.copy2(root / "tests" / "unit.cpp", work / "tests" / "unit.cpp")
subprocess.run([
    "x86_64-w64-mingw32-g++-posix", "-O2", "-std=c++17", "-DUNICODE",
    "-D_UNICODE", "-D_WIN32_WINNT=0x0A00", "-s", "-static",
    "-static-libgcc", "-static-libstdc++", "-municode", "-o", str(root / "build" / "oldcallback.exe"),
    str(work / "tests" / "unit.cpp"), "-ladvapi32", "-lsecur32", "-lole32",
    "-luuid", "-lcredui", "-lwtsapi32",
], check=True)
print("Former PLAP-only mutant built; require failure in Windows unit tests.")
