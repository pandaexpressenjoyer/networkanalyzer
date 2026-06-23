CXX = g++
CXXFLAGS = -std=c++17 -Wall -Idependancies/npcap-sdk-1.16/Include

# Configure Linker Paths and Libraries
LDFLAGS = -Ldependancies/npcap-sdk-1.16/Lib/x64 -lwpcap -lpacket -lws2_32

# Target Executable
TARGET = network_analyzer.exe
SRCS = src/main.cpp

# Build Rules
all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

# Clean rule 
clean:
	del /Q $(TARGET)