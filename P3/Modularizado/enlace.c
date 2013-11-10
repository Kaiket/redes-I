#include "enlace.h"

/*
 * Se vuelva los primeros ETH_HLEN bytes del paquete en la estructura ethernet.
 */
struct_ethernet leerEthernet(u_int8_t* paquete){
    struct_ethernet se;
    memcpy(&se, paquete, ETH_HLEN);
    return se;
}


/*
 * Imprime la informacion de la cabecera ethernet del paquete en el standard
 * output.
 */
void printEthernet(struct_ethernet cabecera) {
    
    int i;
    
    printf("Cabecera Ethernet\n");
    
    /*Ethernet origen*/
    printf("Direccion ethernet Origen: ");
    for (i = 0; i < ETH_ALEN; ++i) {
        printf("%02x", cabecera.origen[i]);
        if (i != ETH_ALEN-1){
            printf(":");
        }
    }
    printf("\n");
    
    /*Ethernet destino*/
    printf("Direccion ethernet Destino: ");
    for (i = 0; i < ETH_ALEN; ++i) {
        printf("%02x", cabecera.destino[i]);
        if (i!=ETH_ALEN-1){
            printf(":");
        }
    }
    printf("\n");
}

/*
 * Comprueba el campo de tipo de ethernet para ver si el paquete es IP o no.
 */
int enlace_esIP(struct_ethernet se){
    if(ntohs(se.tipoEth) == ETH_IPTYPE){
        return TRUE;
    }
    return FALSE;
}

/*
 * Guarda en el array de enteros "MAC" la direccion mac contenida en "cadena", 
 * eliminando los ":"
 */
int scan_eth (u_int8_t* MAC, char* cadena) {
    int i = 0, j;
    char* aux, *ret;
    
    /*Control de errores*/
    if (!MAC || !cadena) {
        return ERROR;
    }
    
    aux = cadena;
    
    /*Guardamos en MAC los valores numericos sin los ":" de la cadena*/
    while ((ret=strtok(aux, ":")) != NULL && i<ETH_ALEN) {
        
        if(strlen(ret) > 2){
            return ERROR_FILTRO;
        }
        
        for(j = 0; j < strlen(ret); ++j){
            if(!((ret[j] <= '9' && ret[j] >= '0') ||
                 (ret[j] <= 'f' && ret[j] >= 'a') ||
                 (ret[j] <= 'F' && ret[j] >= 'A') )){
                return ERROR_FILTRO;
            }
        }
        sscanf(ret, "%02x", &(MAC[i]));
        aux=NULL;
        i++;
    }
    /*Si no hemos leido tantos numeros como tiene la direccion MAC se devuelve error.*/
    if (i != ETH_ALEN) {
        return ERROR;
    }
    return OK;
}
