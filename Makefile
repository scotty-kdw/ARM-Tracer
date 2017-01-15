.SUFFIXES = .c .o

CC = arm-linux-androideabi-gcc 

CAPSTONE_INCLUDE = $(PWD)/capstone
CAPSTONE_LIBRARY = $(PWD)/capstone

TARGET = ARM-Tracer
SOURCE = tracer.c utils.c arm_arm_next_pc.c arm_thumb_next_pc.c
OBJECT = tracer.o utils.o arm_arm_next_pc.o arm_thumb_next_pc.o


all : $(TARGET)

$(TARGET) : $(SOURCE)
	$(CC) -g -o $(TARGET) $(SOURCE) -I$(CAPSTONE_INCLUDE) -L$(CAPSTONE_LIBRARY) -lcapstone

clean:
	rm -rf $(TARGET)
	rm -rf $(OBJECT)
