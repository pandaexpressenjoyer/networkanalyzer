# Compiler settings
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Idependancies/npcap-sdk-1.16/Include -Iinc

# Linker settings for Npcap and Windows socket architectures
LDFLAGS = -Ldependancies/npcap-sdk-1.16/Lib/x64 -lwpcap -lpacket -lws2_32

# Build configuration targeting all source files
TARGET = network_analyzer.exe
SRCS = src/main.cpp src/packet_handler.cpp src/metrics.cpp

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

clean:
	del /Q $(TARGET)