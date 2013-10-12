/***************************************************************************
 * Autores: Enrique Cabrerizo Fernández, Guillermo Ruiz Álvarez
 * Archivo: practica2.h
 ****************************************************************************/

#ifndef __PRACTICA2_H
#define __PRACTICA2_H

/*
 * Analiza un paquete imprimiendo en el standard output la informacion
 * del mismo.
 * Recibe: Puntero al inicio del paquete, cabecera del paquete, contador de paquetes.
 * Devuelve: 0 si no han habido errores.
 *	     1 si se le pasan argumentos invalidos (e.g punteros a NULL).
 */
u_int8_t analizarPaquete(u_int8_t*, struct pcap_pkthdr*, u_int64_t);



/*
 * Funcion manejadora de la señal Ctrl+C (SIGINT).
 * Recibe: el numero de la señal que se ha enviado, en este caso SIGINT.
 */
void handleSignal(int nsignal);


#endif /*PRACTICA2__H*/
