/***************************************************************************
 * Autores: Enrique Cabrerizo Fernández, Guillermo Ruiz Álvarez
 * Archivo: practica2.h
 ****************************************************************************/

#ifndef __PRACTICA2_H
#define __PRACTICA2_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>

/************************ Definicion de constantes ***********************/
#define ETH_ALEN      6      /* Tamano de direccion ethernet             */
#define ETH_HLEN      14     /* Tamano de cabecera ethernet              */
#define ETH_TLEN      2      /* Tamano del campo tipo ethernet           */
#define ETH_FRAME_MAX 1514   /* Tamano maximo trama ethernet (sin CRC)   */
#define ETH_FRAME_MIN 60     /* Tamano minimo trama ethernet (sin CRC)   */
                             /*                                          */
#define ETH_IPTYPE    0x0800 /* Tipo de ethernet correspondiente a       */
                             /* protocolo IP                             */
#define IP_HLEN       24     /* Tamano de cabecera ip                    */
                             /*                                          */
#define PROTOCOL_TCP  6      /* Protocolo TCP                            */
#define PROTOCOL_UDP  17     /* Protocolo UDP                            */
/*************************************************************************/

/********Tamano maximo y minimo de los datos de una trama ethernet********/
#define ETH_DATA_MAX  (ETH_FRAME_MAX - ETH_HLEN)  /*Tamano maximo	 */
#define ETH_DATA_MIN  (ETH_FRAME_MIN - ETH_HLEN)  /*Tamano minimo	 */
/*************************************************************************/

/* Macros */
#define OK 0
#define ERROR 1
#define N_BYTES 70 /*Esto hay que calcularlo.*/

/*Estructuras*/
struct __attribute__((__packed__)) struct_ethernet {
    u_int8_t destino[ETH_ALEN];
    u_int8_t origen[ETH_ALEN];
    u_int16_t tipoEth;
};

struct __attribute__((__packed__)) struct_ip {
    u_int8_t version_IHL;
    u_int8_t tipoServicio;
    u_int16_t longitud;
    u_int16_t identificacion;
    u_int16_t flags_posicion;
    u_int8_t tiempoDeVida;
    u_int8_t protocolo;
    u_int16_t sumaControlCabecera;
    u_int32_t destino;
    u_int32_t origen;
    u_int8_t opciones[3];
    u_int8_t relleno;
};

struct __attribute__((__packed__)) struct_tcp{
    
};

struct __attribute__((__packed__)) struct_udp{
    
};




/*
 * Analiza un paquete imprimiendo en el standard output la informacion
 * del mismo.
 * Modifica el puntero recibido colocándolo al inicio de los datos.
 * Recibe: Puntero al inicio del paquete, cabecera del paquete, contador de paquetes.
 * Devuelve: 0 si no han habido errores.
 *	     1 si se le pasan argumentos invalidos (e.g punteros a NULL).
 */
u_int8_t analizarPaquete(u_int8_t*, struct pcap_pkthdr*, u_int64_t);


/*
 * Lee la cabecera Ethernet de un paquete.
 * Modifica el puntero recibido colocandolo al inicio de la siguiente cabecera.
 * Recibe: Puntero al inicio del paquete.
 * Devuelve: Estructura con la informacion de la cabecera Ethernet.
 */
struct_ethernet leerEthernet(u_int8_t* paquete);


/*
 * Lee la cabecera IP de un paquete.
 * Modifica el puntero recibido colocandolo al inicio de la siguiente cabecera.
 * Recibe: Puntero al inicio de la cabecera IP del paquete.
 * Devuelve: Estructura con la informacion de la cabecera IP.
 */
struct_ip leerIP(u_int8_t* cabeceraIP);


/*
 * Lee la cabecera TCP de un paquete.
 * Modifica el puntero recibido colocandolo al inicio de la siguiente cabecera.
 * Recibe: Puntero al inicio de la cabecera TCP del paquete.
 * Devuelve: Estructura con la informacion de la cabecera TCP.
 */
struct_ip leerTCP(u_int8_t* cabeceraTCP);


/*
 * Lee la cabecera UDP de un paquete.
 * Modifica el puntero recibido colocandolo al inicio de la siguiente cabecera.
 * Recibe: Puntero al inicio de la cabecera UDP del paquete.
 * Devuelve: Estructura con la informacion de la cabecera UDP.
 */
struct_ip leerUDP(u_int8_t* cabeceraUDP);


/*
 * Funcion manejadora de la señal Ctrl+C (SIGINT).
 * Recibe: el numero de la señal que se ha enviado, en este caso SIGINT.
 */
void handleSignal(int nsignal);


#endif /*PRACTICA2__H*/
