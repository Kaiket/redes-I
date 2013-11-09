.SUFFIXES: .o .c
.c.o:
	$(CC) -c $(CFLAGS) $<


# Macros
CC = gcc
CFLAGS = -g -Wall
SRC = practica3.c enlace.c red.c transporte.c practica3.h enlace.h red.h transporte.h constantes.h
OBJ = practica3.o enlace.o red.o transporte.o


# Reglas explicitas
all: $(OBJ)
	$(CC) $(CFLAGS) -o practica3 $(OBJ) -lpcap

clean:
	$(RM) $(OBJ) practica3

# Reglas implicitas
enlace.o: enlace.c enlace.h
red.o: red.c red.h
transporte.o: transporte.c transporte.h

practica3.o: practica3.c enlace.h red.h transporte.h constantes.h
