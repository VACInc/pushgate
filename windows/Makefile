CXX := x86_64-w64-mingw32-g++-posix
CXXFLAGS := -O2 -Wall -Wextra -Werror -Wno-misleading-indentation -std=c++17 -DUNICODE -D_UNICODE -D_WIN32_WINNT=0x0A00
WINDRES := x86_64-w64-mingw32-windres
LIBS := -ladvapi32 -lsecur32 -lole32 -luuid -lcredui -lwtsapi32
all: build/PushGateWin.dll
build/PushGateWin.dll: src/provider.cpp src/gate.cpp src/gate.h src/scope.h build/version.o
	mkdir -p build
	$(CXX) $(CXXFLAGS) -shared -s -static -static-libgcc -static-libstdc++ -o $@ src/provider.cpp src/gate.cpp build/version.o $(LIBS)
build/unit.exe: tests/unit.cpp src/provider.cpp src/gate.h src/scope.h
	mkdir -p build
	$(CXX) $(CXXFLAGS) -s -static -static-libgcc -static-libstdc++ -municode -o $@ tests/unit.cpp $(LIBS)
build/packed.exe: tests/packed.cpp src/gate.cpp src/gate.h src/scope.h
	mkdir -p build
	$(CXX) $(CXXFLAGS) -s -static -static-libgcc -static-libstdc++ -o $@ tests/packed.cpp src/gate.cpp $(LIBS)
build/load.exe: tests/load.cpp
	mkdir -p build
	$(CXX) $(CXXFLAGS) -municode -s -static -static-libgcc -static-libstdc++ -o $@ tests/load.cpp $(LIBS)
build/password.exe: tests/password.cpp src/gate.cpp src/gate.h src/scope.h
	mkdir -p build
	$(CXX) $(CXXFLAGS) -s -static -static-libgcc -static-libstdc++ -o $@ tests/password.cpp src/gate.cpp $(LIBS) -lnetapi32

build/scope.exe: tests/scope.cpp src/gate.h src/scope.h
	mkdir -p build
	$(CXX) $(CXXFLAGS) -s -static -static-libgcc -static-libstdc++ -o $@ tests/scope.cpp $(LIBS)

build/version.o: src/version.rc
	mkdir -p build
	$(WINDRES) $< -O coff -o $@
