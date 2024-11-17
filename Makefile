CC = gcc

# Defined the path for -o (executable)
TARGET = src/packetSniffer/bin/packet_sniffer

SRC = src/packetSniffer/main.c

LIBS = -lpcap

#  What dis doing?
all: $(TARGET) 

$(TARGET): $(SRC)
	$(CC) $(SRC) -o $(TARGET) $(LIBS)

clean || clear:
	rm -f $(TARGET)
