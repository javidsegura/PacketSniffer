CC = gcc

TARGET = src/packet_sniffer

SRC = src/packet_sniffer.c

LIBS = -lpcap

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(SRC) -o $(TARGET) $(LIBS)

clean || clear:
	rm -f $(TARGET)
