#include "red.h"

/*
 * Vuelca la información de la cabecera IP en la estructura que devuelve.
 */
struct_ip leerIP(u_int8_t* cabeceraIP){
    struct_ip si;
    memcpy(&si, cabeceraIP, IP_HLEN);
    return si;
   
}

/*
 * Imprime la informacion de la cabecera IP del paquete.
 * Al multiplicar por cuatro el IHL obtenemos el tamaño de la cabecera en bytes,
 * en lugar de en palabras de 32 bits.
 */
void printIP(struct_ip cabecera) {
    
    int i;
    printf("Cabecera IP\n");
    
    /*Información de la cabecera del datagrama.*/
    printf("Version IP: %u\n", (cabecera.version_IHL)>>4);
    printf("IHL: %u bytes\n", (cabecera.version_IHL&0xF)*4);
    printf("Longitud Total: %u\n", ntohs(cabecera.longitud));
    printf("Posicion: %u\n", ntohs(cabecera.flags_posicion)&0x1FFF); 
    printf("Tiempo de Vida: %u\n", cabecera.tiempoDeVida);
    printf("Protocolo: %u\n", cabecera.protocolo);
    
    
    /*Direccion IP origen*/
    printf ("Direccion IP Origen: ");
    for (i=0; i<IP_ALEN; i++) {
        printf("%u", cabecera.origen[i]);
        if (i!=IP_ALEN-1) printf(".");
    }
    printf("\n");
    
    /*Dirección IP destino*/
    printf ("Direccion IP Destino: ");
    for (i=0; i<IP_ALEN; i++) {
        printf("%u", cabecera.destino[i]);
        if (i!=IP_ALEN-1) printf(".");
    }
    printf("\n");
}

/*
 * Comprueba si un paquete es TCP
 */
int red_esTCP(struct_ip si){
    if(si.protocolo == PROTOCOL_TCP){
        return TRUE;
    }
    return FALSE;
}

/*
 * Comprueba si un paquete es UDP
 */
int red_esUDP(struct_ip si){
    if(si.protocolo == PROTOCOL_UDP){
        return TRUE;
    }
    return FALSE;
}

/*
 * Se utiliza strtok para la separacion de la cadena por el delimitador ".".
 * Se comprueba que el valor en cada caso este en [0, 255].
 * Se comprueba que se hayan leido exactamente IP_ALEN bytes.
 */
int scan_ip (u_int8_t* IP, char* cadena) {
    
    int i = 0;
    char *aux, *ret;
    
    /*Control de errores.*/
    if (!IP || !cadena){
        return ERROR;
    }
    
    /*Trabajamos con un puntero auxiliar*/
    aux = cadena;
    
    /*Se guarda en IP los valores numericos (sin los puntos) de la cadena.*/
    while ((ret=strtok(aux,".")) != NULL && i<IP_ALEN) {
        /*Se descartan valores que no esten en [0, 255]*/
        if(atoi(ret) < 0 || atoi(ret) > 255){
            return ERROR;
        }
        sscanf(ret, "%" SCNu8, &(IP[i]));
        aux=NULL;
        i++;
    }
    
    /*Si no hemos leido tantos numeros como tiene la direccion IP se devuelve
      error. */
    if (i != IP_ALEN){
        return ERROR;
    }  
    return OK;
}

/*
 * Imprimimos en el archivo la información de tiempo, tamaño e IP para origen y
 * destino
 */
void exportIPinfo(FILE* archivo, struct pcap_pkthdr* cabecera, struct_ip si) {
    
    int i;
    
    /*Control de errores*/
    if (!archivo || !cabecera){
        return;
    }
    
    /*Imprimimos en el archivo el tiempo, tamaño e IP origen*/
    fprintf(archivo, "%lu\t%lu\t%lu\t" ,cabecera->ts.tv_sec, 
                                        cabecera->ts.tv_usec, 
                                        cabecera->len);
    for (i=0; i<IP_ALEN; i++) {
        fprintf(archivo,"%u", si.origen[i]);
        if (i!=IP_ALEN-1){ 
            fprintf(archivo,".");
        }
    }
    fprintf(archivo, "\n");
    
    /*Imprimimos en el archivo el tiempo, tamaño e IP destino*/
    fprintf(archivo, "%lu\t%lu\t%lu\t" ,cabecera->ts.tv_sec,
                                        cabecera->ts.tv_usec, 
                                        cabecera->len);
    
    for (i=0; i<IP_ALEN; i++) {
        fprintf(archivo,"%u", si.destino[i]);
        if (i!=IP_ALEN-1){ 
            fprintf(archivo,".");
        }
    }
    fprintf(archivo, "\n");
}