# Macros
CC = gcc
OBJ = practica3.o enlace.o red.o transporte.o


# Reglas explicitas
all: $(OBJ)
	$(CC) -o practica3 $(OBJ) -lpcap

clean:
	$(RM) $(OBJ) practica3

# Reglas implicitas
enlace.o:
	gcc -c enlace.c enlace.h
red.o: 
	gcc -c red.c red.h
transporte.o:
	gcc -c transporte.c transporte.h

practica3.o: 
	gcc -c practica3.c enlace.h red.h transporte.h constantes.h
