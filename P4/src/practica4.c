/***************************************************************************
Fecha: 18 Nov 2013
Redes de comunicaciones I
Inicio, funciones auxiliares y modulos de transmision de la practica4
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include "interface.h"
#include "practica4.h"

/* Variables globales utiles */
pcap_t *descr, *descr2; /* Descriptores de la interface de red */
pcap_dumper_t *pdumper; /* y salida a pcap */
uint64_t cont = 0;      /* Contador numero de mensajes enviados */
char *interface;        /* Interface donde transmitir por ejemplo "eth0" */
uint16_t ID = 1;        /* Identificador IP */
uint16_t MTU;

void handleSignal(int nsignal) {
    printf("Control C pulsado (%" SCNd64 ")\n", cont);
    pcap_close(descr);
    pcap_dump_close(pdumper);
    pcap_close(descr2);
    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {

    char errbuf[PCAP_ERRBUF_SIZE];
    char fichero_pcap_destino[CADENAS];
    uint8_t IP_destino_red[IP_ALEN];
    uint16_t datalink;
    uint16_t puerto_destino;
    char data[IP_DATAGRAM_MAX];
    uint16_t pila_protocolos[CADENAS];

    /* Proceso de argumentos */
    /* Dos opciones: leer de stdin o de fichero, adicionalmente para pruebas 
     * si no se introduce argumento se considera que el mensaje es 
     * "Payload " */
    if (argc != 5 && argc != 4) {
        printf("Ejecucion: %s interface IP Puerto </ruta/fichero_a_transmitir o"
                " stdin> \n", argv[0]);
        return ERROR;
    }
    if (argc == 5) {
        if (strcmp(argv[4], "stdin") == 0) {
            if (fgets(data, sizeof data, stdin) == NULL) {
                printf("Error leyendo desde stdin: %s %s %d.\n", errbuf, 
                        __FILE__, __LINE__);
                exit(EXIT_FAILURE);
            }
            sprintf(fichero_pcap_destino, "%s%s", "stdin", ".pcap");
        } else {
            sprintf(fichero_pcap_destino, "%s%s", argv[4], ".pcap");
            if(fichero_a_string(data, argv[4], IP_DATAGRAM_MAX) == ERROR){
                printf("Error leyendo desde fichero: %s %s %d.\n", argv[4], 
                        __FILE__, __LINE__);
                exit(EXIT_FAILURE);
            }     
        }
    }
    else {
        sprintf(data, "%s", "Payload ");
        sprintf(fichero_pcap_destino, "%s%s", "debugging", ".pcap");
    }
    
    /* Captura de señal SIGINT */
    if (signal(SIGINT, handleSignal) == SIG_ERR) {
        printf("Error: Fallo al capturar la senal SIGINT.\n");
        return ERROR;
    }
    /* Inicializacion de las tablas de protocolos */
    if (inicializarPilaEnviar() == ERROR) {
        printf("Error leyendo desde stdin: %s %s %d.\n", errbuf, __FILE__, __LINE__);
        return ERROR;
    }
    /* Por comodidad definimos interface como una variable global */
    interface = argv[1];
    /* Leemos la IP a donde transmitir y la almacenamos en orden de red */
    if (sscanf(argv[2], "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"", 
            &(IP_destino_red[0]), &(IP_destino_red[1]), &(IP_destino_red[2]), 
            &(IP_destino_red[3])) != IP_ALEN) {
        
        printf("Error: Fallo en la lectura IP destino %s\n", argv[2]);
        return ERROR;
        
    }
    /* Leemos el puerto a donde transmitir y la almacenamos en orden de 
     * hardware */
    puerto_destino = atoi(argv[3]);
    /* Leemos el tamano maximo de transmision del nivel de enlace */
    if (obtenerMTUInterface(interface, &MTU) == ERROR)
        return ERROR;
    /* Descriptor de la interface de red donde inyectar trafico */
    if ((descr = pcap_open_live(interface, MTU + ETH_HLEN, 0, 0, errbuf)) == NULL) {
        printf("Error: pcap_open_live(): %s %s %d.\n", errbuf, __FILE__, __LINE__);
        return ERROR;
    }
    datalink = (uint16_t) pcap_datalink(descr); /* DLT_EN10MB==Ethernet */
    /* Descriptor del fichero de salida pcap para debugging */
    descr2 = pcap_open_dead(datalink, MTU + ETH_HLEN);
    pdumper = pcap_dump_open(descr2, fichero_pcap_destino);

    /*Formamos y enviamos el trafico, debe enviarse un unico segmento por 
     * llamada a enviar() aunque luego se traduzca en mas de un datagrama
     * Primero un paquete UDP 
     * Definimos la pila de protocolos que queremos seguir */
    pila_protocolos[0] = UDP_PROTO;
    pila_protocolos[1] = IP_PROTO;
    pila_protocolos[2] = ETH_PROTO;
    /* Rellenamos los parametros necesario para enviar el paquete a su 
     * destinatario y proceso */
    Parametros parametros_udp;
    memcpy(parametros_udp.IP_destino, IP_destino_red, IP_ALEN);
    parametros_udp.puerto_destino = puerto_destino;
    /*Enviamos*/
    if (enviar((uint8_t*) data, pila_protocolos, strlen(data), &parametros_udp) == ERROR) {
        printf("Error: enviar(): %s %s %d.\n", errbuf, __FILE__, __LINE__);
        return ERROR;
    } else cont++;

    printf("Enviado mensaje %lld, almacenado en %s\n\n\n", cont, fichero_pcap_destino);

//    //Luego un paquete ICMP en concreto un ping
//    pila_protocolos[0] = ICMP_PROTO;
//    pila_protocolos[1] = IP_PROTO;
//    pila_protocolos[2] = 0;
//    Parametros parametros_icmp;
//    parametros_icmp.tipo = PING_TIPO;
//    parametros_icmp.codigo = PING_CODE;
//    memcpy(parametros_icmp.IP_destino, IP_destino_red, IP_ALEN);
//    if (enviar((uint8_t*) "Probando a hacer un ping", pila_protocolos, strlen("Probando a hacer un ping"), &parametros_icmp) == ERROR) {
//        printf("Error: enviar(): %s %s %d.\n", errbuf, __FILE__, __LINE__);
//        return ERROR;
//    } else cont++;
//    printf("Enviado mensaje %lld, ICMP almacenado en %s\n\n", cont, fichero_pcap_destino);

    //Cerramos descriptores
    pcap_close(descr);
    pcap_dump_close(pdumper);
    pcap_close(descr2);
    return OK;
}

/****************************************************************************************
 * Nombre: enviar 									*
 * Descripcion: Esta funcion envia un mensaje						*
 * Argumentos: 										*
 *  -mensaje: mensaje a enviar								*
 *  -pila_protocolos: conjunto de protocolos a seguir					*
 *  -longitud: bytes que componen mensaje						*
 *  -parametros: Parametros necesario para el envio (struct parametros)			*
 * Retorno: OK/ERROR									*
 ****************************************************************************************/

uint8_t enviar(uint8_t* mensaje, uint16_t* pila_protocolos, uint64_t longitud, void *parametros) {
    uint16_t protocolo = pila_protocolos[0];
    printf("Enviar(%u) %s %d.\n", protocolo, __FILE__, __LINE__);
    if (protocolos_registrados[protocolo] == NULL) {
        printf("Protocolo %"SCNu16" desconocido\n", protocolo);
        return ERROR;
    } else {
        return protocolos_registrados[protocolo](mensaje, pila_protocolos, longitud, parametros);
    }
    return ERROR;
}


/***************************Pila de protocolos a implementar************************************/

/****************************************************************************************
 * Nombre: moduloUDP 									*
 * Descripcion: Esta funcion implementa el modulo de envio UDP				*
 * Argumentos: 										*
 *  -mensaje: mensaje a enviar								*
 *  -pila_protocolos: conjunto de protocolos a seguir					*
 *  -longitud: bytes que componen mensaje						*
 *  -parametros: Parametros necesario para el envio este protocolo			*
 * Retorno: OK/ERROR									*
 ****************************************************************************************/

uint8_t moduloUDP(uint8_t* mensaje, uint16_t* pila_protocolos, uint64_t longitud, void *parametros) {
    uint8_t segmento[UDP_SEG_MAX] = {0};
    uint16_t puerto_origen, suma_control = 0;
    uint16_t aux16;
    uint32_t pos = 0;
    uint16_t protocolo_inferior = pila_protocolos[1];
    printf("moduloUDP(%u) %s %d.\n", protocolo_inferior, __FILE__, __LINE__);
    Parametros udpdatos = *((Parametros*) parametros);
    uint16_t puerto_destino = udpdatos.puerto_destino;
    if (longitud + UDP_HLEN > pow(2, 16)) {
        printf("Error: tamano demasiado grande para UDP (%f).\n", (pow(2, 16)-UDP_HLEN));
        return ERROR;
    }

    /*obtenemos un puerto de origen*/
    if (obtenerPuertoOrigen(&puerto_origen)==ERROR){
        printf("Error: No se pudo obtener un puerto para enviar la informacion");
        return ERROR;
    }
    
    /*almacenamos el puerto de origen*/
    aux16 = htons(puerto_origen);
    memcpy(segmento + pos, &aux16, sizeof (uint16_t));
    pos += sizeof (uint16_t);
    
    /*almacenamos el puerto de destino*/
    aux16 = htons(udpdatos.puerto_destino);
    memcpy(segmento + pos, &aux16, sizeof (uint16_t));
    pos += sizeof (uint16_t);
    
    /*almacenamos la longitud (8 octetos de cabecera mas la del mensaje)*/        
    aux16 = htons((uint16_t)(UDP_HLEN+longitud));
    memcpy(segmento + pos, &aux16, sizeof (uint16_t));
    pos += sizeof (uint16_t);
    
    /*el checksum no se calcula*/
    aux16=0;
    memcpy(segmento + pos, &aux16, sizeof(uint16_t));
    pos += sizeof (uint16_t);
    
    /*copiamos el mensaje*/
    memcpy(segmento + pos, mensaje, longitud*sizeof(uint8_t));
    
    //Se llama al protocolo definido de nivel inferior a traves de los punteros registrados en la tabla de protocolos registrados
    return protocolos_registrados[protocolo_inferior](segmento, pila_protocolos, longitud + pos, parametros);
}
/****************************************************************************************
 * Nombre: moduloIP 									*
 * Descripcion: Esta funcion implementa el modulo de envio IP				*
 * Argumentos: 										*
 *  -segmento: segmento a enviar								*
 *  -pila_protocolos: conjunto de protocolos a seguir					*
 *  -longitud: bytes que componen el segmento						*
 *  -parametros: Parametros necesario para el envio este protocolo			*
 * Retorno: OK/ERROR									*
 ****************************************************************************************/

uint8_t moduloIP(uint8_t* segmento, uint16_t* pila_protocolos, uint64_t longitud, void *parametros) {
    int i;
    uint16_t flags = 0;
    uint8_t datagrama[IP_DATAGRAM_MAX] = {0}, *checksumpos;
    uint32_t aux32;
    uint16_t aux16;
    uint8_t aux8;
    uint8_t IP_origen[IP_ALEN];
    uint16_t pos = 0, pos_inicial = 0;
    uint16_t protocolo_superior = pila_protocolos[0];
    uint16_t protocolo_inferior = pila_protocolos[2];
    pila_protocolos++;
    uint8_t mascara[IP_ALEN], IP_rango_origen[IP_ALEN], IP_rango_destino[IP_ALEN];
    uint16_t offset, num_fragmentos;


    printf("moduloIP(%u) %s %d.\n", protocolo_inferior, __FILE__, __LINE__);

    Parametros ipdatos = *((Parametros*) parametros);
    uint8_t* IP_destino = ipdatos.IP_destino;

    if (longitud + IP_HLEN > pow(2, 16)) {
        printf("Error: tamano demasiado grande para IP.\n");
        return ERROR;
    }


    num_fragmentos = (uint16_t) ceil(((double) longitud) / (MTU - IP_HLEN));
    offset = (MTU - IP_HLEN);

    datagrama[pos] = (uint8_t)0x45;//(0x4 << 4) | (IP_HLEN / 4);
    pos += sizeof (uint8_t);
    datagrama[pos] = 0x0;
    pos += sizeof (uint8_t);
    pos_inicial = pos;
    for (i = 0; i < num_fragmentos; i++) {
        pos = pos_inicial;
        if (i != num_fragmentos - 1) { /*ultimo fragmento*/
            aux16 = htons(MTU);
            memcpy(datagrama + pos, &aux16, sizeof (uint16_t));
            pos += sizeof (uint16_t);
            flags = 1;
        } else {
            aux16 = htons((longitud - (MTU - IP_HLEN)*(num_fragmentos - 1)) + IP_HLEN);
            memcpy(datagrama + pos, &aux16, sizeof (uint16_t));
            pos += sizeof (uint16_t);
            flags = 0;
        }
        aux16 = htons(ID);
        memcpy(datagrama + pos, &aux16, sizeof (uint16_t));
        pos += sizeof (uint16_t);

        aux16 = htons((flags << 13) | (i * offset / 8));
        memcpy(datagrama + pos, &aux16, sizeof (uint16_t));
        pos += sizeof (uint16_t);

        datagrama[pos] = 0x80;
        pos += sizeof (uint8_t);

        datagrama[pos] = (uint8_t) protocolo_superior;
        pos += sizeof (uint8_t);

        aux16 = 0;
        memcpy(datagrama + pos, &aux16, sizeof (uint16_t));
        checksumpos = datagrama + pos;
        pos += sizeof (uint16_t);

        if (obtenerIPInterface(interface, IP_origen) == ERROR) {
            return ERROR;
        }

        memcpy(datagrama + pos, IP_origen, IP_ALEN * sizeof (uint8_t));
        pos += IP_ALEN * sizeof (uint8_t);

        memcpy(datagrama + pos, ipdatos.IP_destino, IP_ALEN * sizeof (uint8_t));
        pos += IP_ALEN * sizeof (uint8_t);

        if (calcularChecksum(IP_HLEN, datagrama, &aux16) == ERROR) {
            return ERROR;
        }
        memcpy(checksumpos, &aux16, sizeof (uint16_t));

        if (i != num_fragmentos - 1) {
            memcpy(datagrama + pos, segmento + i*offset, (MTU-IP_HLEN)*sizeof(uint8_t));
        } else {
            memcpy(datagrama + pos, segmento + i*offset, (longitud-(MTU-IP_HLEN)*(num_fragmentos-1))*sizeof(uint8_t));
        }
        
        if(protocolos_registrados[protocolo_inferior](segmento, pila_protocolos, longitud + pos, parametros) == ERROR){
            return ERROR;
        }

    }
}

/****************************************************************************************
 * Nombre: moduloETH 									*
 * Descripcion: Esta funcion implementa el modulo de envio Ethernet			*
 * Argumentos: 										*
 *  -datagrama: datagrama a enviar							*
 *  -pila_protocolos: conjunto de protocolos a seguir					*
 *  -longitud: bytes que componen el datagrama						*
 *  -parametros: Parametros necesario para el envio este protocolo			*
 * Retorno: OK/ERROR									*
 ****************************************************************************************/

uint8_t moduloETH(uint8_t* datagrama, uint16_t* pila_protocolos, uint64_t longitud, void *parametros) {

    uint8_t MAC[ETH_ALEN];    
    Parametros ethdatos = *((Parametros*) parametros);
    uint16_t pos = 0;
    uint16_t protocolo_superior = pila_protocolos[0];
    pila_protocolos++;
    uint16_t aux16;
    struct pcap_pkthdr pkthdr;
    
    if(longitud > MTU){
        return ERROR;
    }
    
    printf("moduloETH(fisica) %s %d.\n", __FILE__, __LINE__);
    uint8_t trama[ETH_FRAME_MAX] = {0};

    if(ARPrequest(interface, ethdatos.IP_destino, MAC) == ERROR){
        return ERROR;
    }
    
    //[...] Cabecera del modulo a implementar
    memcpy(trama + pos, MAC, ETH_ALEN*sizeof(uint8_t));
    pos += ETH_ALEN*sizeof(uint8_t);
    
    if(obtenerMACdeInterface(interface, MAC) == ERROR){
        return ERROR;
    }
    memcpy(trama + pos, MAC, ETH_ALEN*sizeof(uint8_t));
    pos += ETH_ALEN*sizeof(uint8_t);
    
    aux16 = htons(protocolo_superior);
    memcpy(trama + pos, &aux16, sizeof(uint16_t));
    pos += sizeof(uint16_t);

    memcpy(trama + pos, datagrama, longitud*sizeof(uint8_t));

    /* Enviar a capa fisica a implementar. */
    if(pcap_inject(descr, trama, longitud + ETH_HLEN) == -1){
        return ERROR;
    }
    
    /* Almacenamos la salida por cuestiones de debugging a implementar. */
    pkthdr.len = longitud + ETH_HLEN;
    pkthdr.caplen = longitud + ETH_HLEN;
    gettimeofday(&(pkthdr.ts), NULL);
    
    pcap_dump((u_char*) pdumper, &pkthdr, (u_char*) trama);
    
    return OK;
}

/****************************************************************************************
 * Nombre: moduloICMP 									*
 * Descripcion: Esta funcion implementa el modulo de envio ICMP				*
 * Argumentos: 										*
 *  -mensaje: mensaje a anadir a la cabecera ICMP					*
 *  -pila_protocolos: conjunto de protocolos a seguir					*
 *  -longitud: bytes que componen el mensaje						*
 *  -parametros: Parametros necesario para el envio este protocolo			*
 * Retorno: OK/ERROR									*
 ****************************************************************************************/

uint8_t moduloICMP(uint8_t* mensaje, uint16_t* pila_protocolos, uint64_t longitud, void *parametros) {
    //Modulo ICMP a implementar
    //[....]

}


/***************************Funciones auxiliares a implementar***********************************/

/****************************************************************************************
 * Nombre: aplicarMascara 								*
 * Descripcion: Esta funcion aplica una mascara a una vector				*
 * Argumentos: 										*
 *  -IP: IP a la que aplicar la mascara en orden de red					*
 *  -mascara: mascara a aplicar en orden de red						*
 *  -longitud: bytes que componen la direccion (IPv4 == 4)				*
 *  -resultado: Resultados de aplicar mascara en IP en orden red				*
 * Retorno: OK/ERROR									*
 ****************************************************************************************/

uint8_t aplicarMascara(uint8_t* IP, uint8_t* mascara, uint32_t longitud, uint8_t* resultado) {
    //A implementar
    //[...]
}


/***************************Funciones auxiliares implementadas**************************************/

/****************************************************************************************
 * Nombre: mostrarPaquete 								*
 * Descripcion: Esta funcion imprime por pantalla en hexadecimal un vetor		*
 * Argumentos: 										*
 *  -paquete: bytes que conforman un paquete						*
 *  -longitud: Bytes que componen el mensaje						*
 * Retorno: OK/ERROR									*
 ****************************************************************************************/

uint8_t mostrarPaquete(uint8_t * paquete, uint32_t longitud) {
    uint32_t i;
    printf("Paquete:\n");
    for (i = 0; i < longitud; i++) {
        printf("%02X ", paquete[i]);
    }
    printf("\n");
    return OK;
}

/****************************************************************************************
 * Nombre: calcularChecksum							     	*
 * Descripcion: Esta funcion devuelve el ckecksum tal como lo calcula IP/ICMP		*
 * Argumentos:										*
 *   -longitud: numero de bytes de los datos sobre los que calcular el checksum		*
 *   -datos: datos sobre los que calcular el checksum					*
 *   -checksum - checksum de los datos (2 bytes) en orden de red  			*
 * Retorno: OK/ERROR									*
 ****************************************************************************************/

uint8_t calcularChecksum(uint16_t longitud, uint8_t *datos, uint8_t *checksum) {
    uint16_t word16;
    uint32_t sum = 0;
    int i;
    // make 16 bit words out of every two adjacent 8 bit words in the packet
    // and add them up
    for (i = 0; i < longitud; i = i + 2) {
        word16 = (datos[i] << 8) + datos[i + 1];
        sum += (uint32_t) word16;
    }
    // take only 16 bits out of the 32 bit sum and add up the carries
    while (sum >> 16) {
        sum = (sum & 0xFFFF)+(sum >> 16);
    }
    // one's complement the result
    sum = ~sum;
    checksum[0] = sum >> 8;
    checksum[1] = sum & 0xFF;
    return OK;
}


/* Funciones inicializacion implementadas */

/*
 * Nombre: inicializarPilaEnviar     							
 * Descripcion: inicializar la pila de red para enviar registrando los 
 * distintos modulos
 * Retorno: OK/ERROR									
 */
uint8_t inicializarPilaEnviar() {
    bzero(protocolos_registrados, MAX_PROTOCOL * sizeof (pf_notificacion));
    if (registrarProtocolo(ETH_PROTO, moduloETH, protocolos_registrados))
        return ERROR;
    if (registrarProtocolo(IP_PROTO, moduloIP, protocolos_registrados))
        return ERROR;
    if (registrarProtocolo(UDP_PROTO, moduloUDP, protocolos_registrados))
        return ERROR;
    if (registrarProtocolo(ICMP_PROTO, moduloICMP, protocolos_registrados))
        return ERROR;
    
    //A registrar los modulos de UDP y ICMP [...] 

    return OK;
}

/*
 * Nombre: registrarProtocolo 								
 * Descripcion: Registra un protocolo en la tabla de protocolos 			
 * Argumentos:										
 *  -protocolo: Referencia del protocolo (ver RFC 1700)					
 *  -handleModule: Funcion a llamar con los datos a enviar				
 *  -protocolos_registrados: vector de funciones registradas 				
 * Retorno: OK/ERROR 									
 */

uint8_t registrarProtocolo(uint16_t protocolo, pf_notificacion handleModule, 
        pf_notificacion* protocolos_registrados) {
    
    if (protocolos_registrados == NULL || handleModule == NULL) {
        printf("Error: registrarProtocolo(): entradas nulas.\n");
        return ERROR;
    } 
    else {
        protocolos_registrados[protocolo] = handleModule;        
    }

    return OK;
}


uint8_t fichero_a_string(char *string_dest, char *nombre_fichero, size_t tam){

    FILE *f;
    char lectura[tam];
    uint32_t offset = 0;

    /*Control de errores*/
    if (!string_dest || !nombre_fichero) {
        return ERROR;
    }

    /*Apertura del fichero en modo lectura*/
    if ((f = fopen(nombre_fichero, "r")) == NULL) {
        return ERROR;
    }

    /*Lectura del fichero*/
    while (fgets(lectura, tam, f) != NULL) {
        /*Se almacena un maximo de tam*/
        if (strlen(lectura) + offset > tam) {
            strncpy(string_dest + offset, lectura, tam - offset);
            return OK;
        }
        strncpy(string_dest + offset, lectura, strlen(lectura));
        offset += strlen(lectura);
    }
    
    fclose(f);

    return OK;
    
}
