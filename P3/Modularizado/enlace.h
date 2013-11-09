/* 
 * Archivo: enlace.h
 * Autores: Enrique Cabrerizo Fernández, Guillermo Ruiz Álvarez.
 * Fecha: Noviembre 2013.
 *  
 * Funciones de manejo de la cabecera de enlace Ethernet.
 */

#ifndef ENLACE_H
#define	ENLACE_H

#include "constantes.h"
#include <stdint.h>
#include <inttypes.h>

/*Estructura para la cabecera Ethernet*/
typedef struct __attribute__ ((__packed__)) struct_ethernet {
    u_int8_t destino[ETH_ALEN]; /*Dirección Ethernet Destino*/
    u_int8_t origen[ETH_ALEN];  /*Dirección Ethernet Origen*/
    u_int16_t tipoEth;          /*Tipo de ethernet*/
} struct_ethernet;


/*Prototipos de funciones*/

/*
 * Lee la cabecera Ethernet de un paquete.
 * Recibe: Puntero al inicio del paquete.
 * Devuelve: Estructura con la informacion de la cabecera Ethernet.
 */
struct_ethernet leerEthernet(u_int8_t* paquete);

/*
 * Imprime la cabecera Ethernet en el standard output.
 * Recibe: Estructura de la cabecera ethernet.
 */
void printEthernet(struct struct_ethernet cabecera);

/*
 * Comprueba si un paquete es IP o no.
 * Recibe: Estrucura ethernet.
 * Devuelve: 1 si es IP, 0 en caso contrario.
 */
int enlace_esIP(struct_ethernet se);

/*
 * Almacena en el entero al que apunta MAC la dirección MAC contenida en cadena.
 * Recibe:  Puntero a entero en el que almacenar la MAC, cadena con la MAC,
 *          con los valores separados por dos puntos. Se admite una cadena de la 
 *          forma xx:xx:xx:xx:xx:xx.
 * Devuelve: 0 si no han habido errores.
 *	     1 si se le pasan argumentos invalidos (e.g punteros a NULL).
 */
int scan_eth (u_int8_t* MAC, char* cadena);



#endif	/* ENLACE_H */

