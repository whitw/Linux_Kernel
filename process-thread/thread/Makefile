CC = gcc
CFLAGS = -W -Wall
THREADFLAGS = -lpthread
OBJS = thread

TARGET = $(OBJS).out

default:
	$(CC) $(CFLAGS) $(OBJS).c -o $(TARGET) $(THREADFLAGS)
clean:
	rm $(TARGET)
