/* 
 * Archivo: constantes.h
 * Autores: Enrique Cabrerizo Fernández, Guillermo Ruiz Álvarez.
 * Fecha: Noviembre 2013. 
 */

#ifndef CONSTANTES_H
#define	CONSTANTES_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>

/*Control de errores*/
#define OK 0
#define ERROR 1
#define ERROR_FILTRO 2   /*El paquete no pasa el filtro*/
#define ERROR_DESCARTE 3 /*Indica que un paquete no es IP, TCP o UDP*/

/*Tipos*/
#define TRUE 1
#define FALSE !(TRUE)

/*Tamaños y protocolos*/
#define ETH_ALEN 6                  /*Tamaño de dirección ethernet.*/
#define ETH_HLEN 14                 /*Tamaño de cabecera ethernet.*/
#define ETH_TLEN 2                  /*Tamaño del campo tipo ethernet.*/
#define ETH_FRAME_MAX 1514          /*Tamaño maximo trama ethernet (sin CRC).*/
#define ETH_FRAME_MIN 60            /*Tamaño minimo trama ethernet (sin CRC).*/
#define ETH_IPTYPE 0x0800           /*Tipo de ethernet IP */
#define IP_ALEN 4                   /*Tamano de direccion IP*/
#define PROTOCOL_TCP 6              /*Protocolo TCP*/
#define PROTOCOL_UDP 17             /*Protocolo UDP*/
#define ETH_DATA_MAX  (ETH_FRAME_MAX - ETH_HLEN) /*Tamaño maximo de datos eth*/
#define ETH_DATA_MIN  (ETH_FRAME_MIN - ETH_HLEN) /*Tamaño minimo de datos eth*/

#endif	/* CONSTANTES_H */
