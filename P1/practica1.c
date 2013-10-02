/***************************************************************************
 * Autores: Enrique Cabrerizo Fernández, Guillermo Ruiz Álvarez
 * Archivo: practica1.c
 * Compilar: gcc -o practica1 practica1.c -lpcap
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>


#define OK 0
#define ERROR 1
#define DEFAULT_NAME "output.pcap"
#define N_BYTES 10

int n_packages;
pcap_t *descr=NULL, *descr2=NULL;
pcap_dumper_t *pdump=NULL;

/*Handle function of SIGINT (Ctrl + C)*/
void handle(int nsignal) {
    printf("Control C pulsado\n");
    printf("Numero de paquetes: %d\n", n_packages);
    pcap_close(descr);
    if (descr2!=NULL) pcap_close(descr2);
    if (pdump!=NULL) pcap_dump_close(pdump);
    exit(0);
}

int main(int argc, char **argv) {
    int i,j;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_char *packet;
    struct pcap_pkthdr h;
    n_packages = 0;

    /*Signal capture SIGINT (Ctrl + C)*/
    if (signal(SIGINT, handle) == SIG_ERR) {
        printf("Error: Fallo al capturar la senal SIGINT.\n");
        exit(EXIT_FAILURE);
    }

    if (argc == 1) { /*if no arguments we are going to read from eth0*/
        /*Reading eth0, max N_BYTES, non-promiscuous mode, unlimited time. */
        if ((descr = pcap_open_live("eth0", N_BYTES, 0, 0, errbuf)) == NULL) {
            printf("Error: pcap_open_live(): %s %s %d.\n", errbuf, __FILE__, __LINE__);
            exit(EXIT_FAILURE);
        }
	/*Opening the file to save the packages*/
	if ((descr2=pcap_open_dead(DLT_EN10MB,N_BYTES)) == NULL) {
	    printf("Error: pcap_open_dead(): %s %d.\n", __FILE__, __LINE__);
	    pcap_close(descr);
            exit(EXIT_FAILURE);
	}
	if ((pdump=pcap_dump_open(descr2, DEFAULT_NAME)) == NULL) {
	    printf("Error: pcap_dump_open(): %s %d.\n", __FILE__, __LINE__);
	    pcap_close(descr);
	    pcap_close(descr2);
            exit(EXIT_FAILURE);
	}
    }
    else {
        /*Reading pcap file.*/
        if ((descr = pcap_open_offline(argv[1], errbuf)) == NULL){
            printf("Error: pcap_open_offline(): %s %s %d.\n", errbuf, __FILE__, __LINE__);
            exit(EXIT_FAILURE);
        }
    }

    /*Reading packages from eth0 / pcapfile*/
    while (1){
	packet = (u_int8_t*) pcap_next(descr, &h);
        if (packet == NULL) {
	    if (argc==1) {
		printf("Error al capturar el paquete %s %d.\n", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	    }
	    else {
		/*Reached end of file*/
		printf("Numero de paquetes: %d\n", n_packages);
		pcap_close(descr);
		if (descr2!=NULL) pcap_close(descr2);
		if (pdump!=NULL) pcap_dump_close(pdump);
		return OK;
	    }
        }
	if (argc==1) pcap_dump((u_char *)pdump, &h, packet);
        printf("Nuevo paquete recibido el %s", ctime((const time_t*) &h.ts.tv_sec));
	printf("Contenido: ");
	/*Printing each byte captured*/
	for (j=0; j< h.caplen; j++) { 
	    printf("%02x ",packet[j]);
	}
	printf("\n");
        ++n_packages;
    }
}

