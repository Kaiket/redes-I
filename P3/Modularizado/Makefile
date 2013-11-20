# Macros
CC = gcc
OBJ = practica3.o enlace.o red.o transporte.o


# Reglas explicitas
all: $(OBJ)
	$(CC) -o practica3 $(OBJ) -lpcap

practica3: $(OBJ)
	$(CC) -o practica3 $(OBJ) -lpcap

main: $(OBJ)
	$(CC) -o main $(OBJ) -lpcap

clean:
	$(RM) $(OBJ) practica3
	$(RM) main
	$(RM) *~
	$(RM) *.h.gch
	$(RM) -rf throughput/
	$(RM) -rf ECDFTamanyos/ 
	$(RM) -rf flujos/
# Reglas implicitas
enlace.o:
	gcc -c enlace.c enlace.h constantes.h
red.o: 
	gcc -c red.c red.h constantes.h
transporte.o:
	gcc -c transporte.c transporte.h constantes.h

practica3.o: 
	gcc -c practica3.c practica3.h enlace.h red.h transporte.h constantes.h

