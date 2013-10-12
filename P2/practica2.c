/***************************************************************************
 * Autores: Enrique Cabrerizo Fernández, Guillermo Ruiz Álvarez
 * Archivo: practica2.c
 ***************************************************************************/

#include <stdio.h>
#include <stdlib.h>

#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>

#include "practica2.h"

/************************ Definicion de constantes ***********************/
#define ETH_ALEN      6      /* Tamano de direccion ethernet             */
#define ETH_HLEN      14     /* Tamano de cabecera ethernet              */
#define ETH_TLEN      2      /* Tamano del campo tipo ethernet           */
#define ETH_FRAME_MAX 1514   /* Tamano maximo trama ethernet (sin CRC)   */
#define ETH_FRAME_MIN 60     /* Tamano minimo trama ethernet (sin CRC)   */
/*************************************************************************/

/********Tamano maximo y minimo de los datos de una trama ethernet********/
#define ETH_DATA_MAX  (ETH_FRAME_MAX - ETH_HLEN)  /*Tamano maximo	 */
#define ETH_DATA_MIN  (ETH_FRAME_MIN - ETH_HLEN)  /*Tamano minimo	 */
/*************************************************************************/

/* Macros */
#define OK 0
#define ERROR 1
#define N_BYTES 10 /*No se cuanto hay que capturar todavia*/

/**/
pcap_t* descr;
u_int64_t cont = 1;

void handleSignal(int nsignal) {
    printf("Control+c pulsado (%lu)\n", cont);
    pcap_close(descr);
    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {

    u_int8_t retorno;                   /*Retorno de analizarPaquete*/
    u_int8_t* paquete;                  /*Inicio del paquete a analizar*/
    struct pcap_pkthdr cabecera;        /*Cabecera del paquete*/
    char errbuf[PCAP_ERRBUF_SIZE];      /*Cadena de error, en su caso*/

    /*Captura de la sena SIGINT*/
    if (signal(SIGINT, handleSignal) == SIG_ERR) {
        printf("Error: Fallo al capturar la senal SIGINT.\n");
        exit(EXIT_FAILURE);
    }

    /**Captura de interfaz / Apertura de fichero pcap**/
    /*Si no se reciben argumentos, se captura eth0*/
    if (argc == 1) {
        if ((descr = pcap_open_live("eth0", N_BYTES, 0, 0, errbuf)) == NULL) {
            printf("Error: pcap_open_live(): %s %s %d", errbuf, __FILE__, __LINE__);
            exit(EXIT_FAILURE);
        }
    }/*En caso contrario se captura el archivo pcap*/
    else {
        if ((descr = pcap_open_offline(argv[1], errbuf)) == NULL) {
            printf("Error: pcap_open_offline(): Archivo: %s, %s %s %d.\n", argv[1], errbuf, __FILE__, __LINE__);
            exit(EXIT_FAILURE);
        }
    }

    /**Lectura de paquetes**/
    if ((paquete = (u_int8_t*) pcap_next(descr, &cabecera)) == NULL) {
        printf("Error al capturar trafico; %s %d.\n", __FILE__, __LINE__);
        exit(EXIT_FAILURE);
    }

    while (paquete) {
        /*Analisis del paquete*/
        if ((retorno = analizarPaquete(paquete, &cabecera, cont)) == ERROR) {
            printf("Error al analizar el paquete %lu; %s %d.\n", __FILE__, __LINE__);
            exit(EXIT_FAILURE);
        }
        paquete = (u_int8_t*) pcap_next(descr, &cabecera);
        ++cont;
    }

    printf("No hay mas paquetes (%lu).\n\n", cont-1, __FILE__, __LINE__);
    pcap_close(descr);

    return EXIT_SUCCESS;
}

u_int8_t analizarPaquete(u_int8_t* paquete, struct pcap_pkthdr* cabecera, u_int64_t cont) {

    int i = 0;
    u_int8_t* paquete_bck = paquete;

    printf("Direccion ETH destino= ");
    printf("%02X", paquete[i]);
    for (i = 1; i < ETH_ALEN; i++) {
        printf(":%02X", paquete[i]);
    }
    printf("\n");
    printf("Direccion ETH origen = ");
    printf("%02X", paquete[i]);
    paquete += ETH_ALEN;
    for (i = 1; i < ETH_ALEN; i++) {
        printf(":%02X", paquete[i]);
    }
    printf("\n");

    //paquete+=ETH_ALEN;
    // .....
    // .....
    // .....

    printf("\n\n");
    return OK;
}

