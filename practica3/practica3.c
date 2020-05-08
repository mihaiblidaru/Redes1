/***************************************************************************
 practica3.c
 Inicio, funciones auxiliares y modulos de transmision implmentados y a implementar de la practica 4.
Compila con warning pues falta usar variables y modificar funciones
 
 Compila: make
 Autor: Jose Luis Garcia Dorado, Jorge E. Lopez de Vergara Mendez
 2018 EPS-UAM v1
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <math.h>
#include <sys/types.h>
#include <unistd.h>
#include "interface.h"
#include "practica3.h"


/***************************Variables globales utiles*************************************************/
pcap_t* descr, *descr2; //Descriptores de la interface de red
pcap_dumper_t * pdumper;//y salida a pcap
uint64_t cont=0;	//Contador numero de mensajes enviados
char interface[10];	//Interface donde transmitir por ejemplo "eth0"
uint16_t ID=1;		//Identificador IP
uint16_t MTU;

char flag_mostrar = 0;

void handleSignal(int nsignal){
	printf("Control C pulsado(%d) (%"PRIu64")\n", nsignal, cont);
	pcap_close(descr);
	exit(OK);
}

int main(int argc, char **argv){	

	char errbuf[PCAP_ERRBUF_SIZE] = "";
	char fichero_pcap_destino[CADENAS];
	uint8_t IP_destino_red[IP_ALEN];

	uint16_t datalink;
	uint16_t puerto_destino;
	char *data = calloc(IP_DATAGRAM_MAX, sizeof(char));
	uint16_t pila_protocolos[CADENAS];
	int tamano_datos;


	int long_index=0;
	char opt;
	char flag_iface = 0, flag_ip = 0, flag_port = 0, flag_file = 0, flag_dontfrag = 0;

	static struct option options[] = {
		{"if",required_argument,0,'1'},
		{"ip",required_argument,0,'2'},
		{"pd",required_argument,0,'3'},
		{"f",required_argument,0,'4'},
		{"d",no_argument,0,'5'},
		{"m",no_argument,0,'6'},
		{"h",no_argument,0,'7'},
		{0,0,0,0}
	};

		//Dos opciones: leer de stdin o de fichero, adicionalmente para pruebas si no se introduce argumento se considera que el mensaje es "Payload "
	while ((opt = getopt_long_only(argc, argv,"1:2:3:4:5:6:7", options, &long_index )) != -1) {
		switch (opt) {

			case '1' :

				flag_iface = 1;
				//Por comodidad definimos interface como una variable global
				sprintf(interface,"%s",optarg);
				break;

			case '2' : 

				flag_ip = 1;
				//Leemos la IP a donde transmitir y la almacenamos en orden de red
				if (sscanf(optarg,"%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"",
				                   &(IP_destino_red[0]),&(IP_destino_red[1]),&(IP_destino_red[2]),&(IP_destino_red[3])) != IP_ALEN){
					printf("Error: Fallo en la lectura IP destino %s\n", optarg);
					exit(ERROR);
				}

				break;

			case '3' :

				flag_port = 1;
				//Leemos el puerto a donde transmitir y la almacenamos en orden de hardware
				puerto_destino=atoi(optarg);
				break;

			case '4' :

				if(strcmp(optarg,"stdin")==0) {
					if (fgets(data, sizeof data, stdin)==NULL) {
						  	printf("Error leyendo desde stdin: %s %s %d.\n",errbuf,__FILE__,__LINE__);
						return ERROR;
					}
					sprintf(fichero_pcap_destino,"%s%s","stdin",".pcap");
				} else {
					sprintf(fichero_pcap_destino,"%s%s",optarg,".pcap");

					FILE* fp = fopen(optarg, "r");
					if(fp == NULL){
						fprintf(stderr, "No se puede abrir el fichero %s\n", optarg);
						return ERROR;
					}

					
					fseek(fp, 0, SEEK_END); // seek to end of file
					tamano_datos = ftell(fp);
					fseek(fp, 0, SEEK_SET);

					data = realloc(data, tamano_datos * sizeof(char));
					
					tamano_datos = fread(data, 1, tamano_datos, fp);
					if(tamano_datos == 0){
						fprintf(stderr, "No se pueden leer los datos del fichero %s\n", optarg);
						fclose(fp);
						return ERROR;
					}

					fclose(fp);
				
				}
				flag_file = 1;
				break;
				
			case '5' :
				flag_dontfrag =1; // El usuario solicita que los paquetes se envien con el bit DF=1.
				break;

			case '6' :
				flag_mostrar =1; // El usuario solicita que se muestren en hexadecimal las tramas enviadas.
				break;

			case '7' : printf("Ayuda. Ejecucion: %s -if interface -ip direccion_IP -pd puerto [-f /ruta/fichero_a_transmitir o stdin] [-d] [-m]: %d\n",argv[0],argc); exit(ERROR);
				break;

			case '?' : 
			default: printf("Error. Ejecucion: %s -if interface -ip direccion_IP -pd puerto [-f /ruta/fichero_a_transmitir o stdin] [-d] [-m]: %d\n",argv[0],argc); exit(ERROR);
				break;
        }
    }

	if ((flag_iface == 0) || (flag_ip == 0) || (flag_port == 0)){
		printf("Error. Ejecucion: %s -if interface -ip direccion_IP -pd puerto [-f /ruta/fichero_a_transmitir o stdin] [-d] [-m]: %d\n",argv[0],argc);
		exit(ERROR);
	} else {
		printf("Interface:\n\t%s\n",interface);
		printf("IP:\n\t%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\n",IP_destino_red[0],IP_destino_red[1],IP_destino_red[2],IP_destino_red[3]);
		printf("Puerto destino:\n\t%"PRIu16"\n",puerto_destino);
		if (flag_dontfrag) printf("Se solicita enviar paquete con bit DF=1\n");
		if (flag_mostrar) printf("Se solicita mostrar las tramas enviadas en hexadecimal\n");
	}

	if (flag_file == 0) {
		sprintf(data,"%s","Payload "); //Deben ser pares!
		sprintf(fichero_pcap_destino,"%s%s","debugging",".pcap");
	}

	if(signal(SIGINT,handleSignal)==SIG_ERR){
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		return ERROR;
	}
	//Inicializamos las tablas de protocolos
	if(inicializarPilaEnviar()==ERROR){
      	printf("Error leyendo desde stdin: %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	//Leemos el tamano maximo de transmision del nivel de enlace
	if(obtenerMTUInterface(interface, &MTU)==ERROR)
		return ERROR;
	//Descriptor de la interface de red donde inyectar trafico
	if ((descr = pcap_open_live(interface,MTU+ETH_HLEN,0, 0, errbuf)) == NULL){
		printf("Error: pcap_open_live(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}

	datalink=(uint16_t)pcap_datalink(descr); //DLT_EN10MB==Ethernet

	//Descriptor del fichero de salida pcap para debugging
	descr2=pcap_open_dead(datalink,MTU+ETH_HLEN);
	pdumper=pcap_dump_open(descr2,fichero_pcap_destino);

	//Formamos y enviamos el trafico, debe enviarse un unico segmento por llamada a enviar() aunque luego se traduzca en mas de un datagrama
	//Primero, un paquete ICMP; en concreto, un ping
	pila_protocolos[0]=ICMP_PROTO; pila_protocolos[1]=IP_PROTO; pila_protocolos[2]=0;
	Parametros parametros_icmp; parametros_icmp.tipo=PING_TIPO; parametros_icmp.codigo=PING_CODE; parametros_icmp.bit_DF=flag_dontfrag; memcpy(parametros_icmp.IP_destino,IP_destino_red,IP_ALEN);
	if(enviar((uint8_t*)ICMP_DATA,strlen(ICMP_DATA),pila_protocolos,&parametros_icmp)==ERROR ){
		printf("Error: enviar(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	else	cont++;
	printf("Enviado mensaje %"PRIu64", ICMP almacenado en %s\n\n", cont,fichero_pcap_destino);

	//Luego, un paquete UDP
	//Definimos la pila de protocolos que queremos seguir
	pila_protocolos[0]=UDP_PROTO; pila_protocolos[1]=IP_PROTO; pila_protocolos[2]=ETH_PROTO;
	//Rellenamos los parametros necesario para enviar el paquete a su destinatario y proceso
	Parametros parametros_udp; memcpy(parametros_udp.IP_destino,IP_destino_red,IP_ALEN); parametros_udp.bit_DF=flag_dontfrag; parametros_udp.puerto_destino=puerto_destino;
	//Enviamos

	if(flag_file == 0){
		tamano_datos = strlen(data);
	}

	if(enviar((uint8_t*)data, tamano_datos,pila_protocolos,&parametros_udp)==ERROR ){
		printf("Error: enviar(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		free(data);
		pcap_close(descr);
		pcap_dump_close(pdumper);
		pcap_close(descr2);
		return ERROR;
	}
	else	cont++;

	printf("Enviado mensaje %"PRIu64", almacenado en %s\n\n\n", cont,fichero_pcap_destino);

	free(data);
		//Cerramos descriptores
	pcap_close(descr);
	pcap_dump_close(pdumper);
	pcap_close(descr2);
	return OK;
}


/****************************************************************************************
 * Nombre: enviar                                                                       *
 * Descripcion: Esta funcion envia un mensaje                                           *
 * Argumentos:                                                                          *
 *  -mensaje: mensaje a enviar                                                          *
 *  -pila_protocolos: conjunto de protocolos a seguir                                   *
 *  -longitud: bytes que componen mensaje                                               *
 *  -parametros: parametros necesario para el envio (struct parametros)                 *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t enviar(uint8_t* mensaje, uint32_t longitud,uint16_t* pila_protocolos,void *parametros){
	uint16_t protocolo=pila_protocolos[0];
printf("Enviar(%"PRIu16") %s %d.\n",protocolo,__FILE__,__LINE__);
	if(protocolos_registrados[protocolo]==NULL){
		printf("Protocolo %"PRIu16" desconocido\n",protocolo);
		return ERROR;
	}
	else {
		return protocolos_registrados[protocolo](mensaje,longitud,pila_protocolos,parametros);
	}
	return ERROR;
}


/***************************TODO Pila de protocolos a implementar************************************/


/****************************************************************************************
 * Nombre: moduloICMP                                                                   *
 * Descripcion: Esta funcion implementa el modulo de envio ICMP                         *
 * Argumentos:                                                                          *
 *  -mensaje: mensaje a anadir a la cabecera ICMP                                       *
 *  -longitud: bytes que componen el mensaje                                            *
 *  -pila_protocolos: conjunto de protocolos a seguir                                   *
 *  -parametros: parametros necesario para el envio este protocolo                      *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t moduloICMP(uint8_t* mensaje, uint32_t longitud, uint16_t* pila_protocolos, void *parametros){
	uint8_t segmento[ICMP_DATAGRAM_MAX]={0};
	static uint16_t num_secuencia = 0;
	uint16_t identificador = getpid();
	u_int16_t checksum;
	Parametros params = *((Parametros*)parametros);
	uint8_t aux8;
	u_int16_t aux16;
	uint32_t pos=0;
	uint8_t protocolo_inferior=pila_protocolos[1];
	printf("modulo ICMP(%"PRIu16") %s %d.\n",protocolo_inferior,__FILE__,__LINE__);
	num_secuencia += 1;

	aux8 = PING_TIPO;
	memcpy(segmento + pos, &aux8, sizeof(uint8_t));
	pos+=sizeof(uint8_t);

	memcpy(segmento + pos, &params.codigo, sizeof(uint8_t));
	pos += sizeof(uint8_t);

	// saltamos la suma de control
	pos += sizeof(uint16_t);
	aux16 = htons(identificador);
	memcpy(segmento + pos, &aux16, sizeof(uint16_t));

	// num secuencia
	pos += sizeof(uint16_t);
	aux16 = htons(num_secuencia);
	memcpy(segmento + pos, &aux16, sizeof(uint16_t));
	
	if((longitud % 2) == 1)
		longitud++;
	
	if(longitud > 40)
		longitud = 40;
	
	pos += sizeof(uint16_t);
	memcpy(segmento + pos, mensaje, longitud);
	pos += longitud;

	calcularChecksum(segmento, pos, (u_int8_t*)(&checksum));
	memcpy(segmento + 2, &checksum, sizeof(u_int16_t));

	return protocolos_registrados[protocolo_inferior](segmento, pos, pila_protocolos, parametros);
}


/****************************************************************************************
 * Nombre: moduloUDP                                                                    *
 * Descripcion: Esta funcion implementa el modulo de envio UDP                          *
 * Argumentos:                                                                          *
 *  -mensaje: mensaje a enviar                                                          *
 *  -longitud: bytes que componen mensaje                                               *
 *  -pila_protocolos: conjunto de protocolos a seguir                                   *
 *  -parametros: parametros necesario para el envio este protocolo                      *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t moduloUDP(uint8_t* mensaje, uint32_t longitud, uint16_t* pila_protocolos, void *parametros){
	uint8_t segmento[UDP_SEG_MAX + 8]={0};
	uint16_t puerto_origen = 0;
	uint16_t aux16;
	uint32_t pos=0;
	uint8_t protocolo_inferior=pila_protocolos[1];
	printf("modulo UDP(%"PRIu16") %s %d.\n",protocolo_inferior,__FILE__,__LINE__);

	if (longitud > UDP_SEG_MAX){
		printf("Error: mensaje demasiado grande para UDP (%d).\n", UDP_SEG_MAX);
		return ERROR;
	}

	Parametros udpdatos=*((Parametros*)parametros);
	uint16_t puerto_destino=udpdatos.puerto_destino;
	if(obtenerPuertoOrigen(&puerto_origen) == ERROR){
		fprintf(stderr, "%s:%d -> No se pudo obtener el puerto origen\n", __FILE__, __LINE__);
		return ERROR;
	}

	aux16=htons(puerto_origen);
	memcpy(segmento+pos,&aux16,sizeof(uint16_t));
	pos+=sizeof(uint16_t);

	aux16=htons(puerto_destino);
	memcpy(segmento+pos,&aux16,sizeof(uint16_t));
	pos+=sizeof(uint16_t);
	
	aux16 = htons(longitud + 8 );
	memcpy(segmento+pos, &aux16, sizeof(uint16_t));
	pos += sizeof(uint16_t) * 2;

	//Copio todos los datos
	memcpy(segmento+pos, mensaje, longitud);

	return protocolos_registrados[protocolo_inferior](segmento,longitud + 8, pila_protocolos, parametros);
}


/****************************************************************************************
 * Nombre: moduloIP                                                                     *
 * Descripcion: Esta funcion implementa el modulo de envio IP                           *
 * Argumentos:                                                                          *
 *  -segmento: segmento a enviar                                                        *
 *  -longitud: bytes que componen el segmento                                           *
 *  -pila_protocolos: conjunto de protocolos a seguir                                   *
 *  -parametros: parametros necesario para el envio este protocolo                      *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t moduloIP(uint8_t* segmento, uint32_t longitud, uint16_t* pila_protocolos, void *parametros){
	uint8_t datagrama[IP_DATAGRAM_MAX]={0};
	static uint16_t idenfiticador = 0;
	uint16_t mtu_ip;
	uint16_t num_fragmentos;
	uint16_t flags_y_pos = 0x0000;
	uint16_t flags = 0x0000;
	uint16_t checksum;
	uint16_t tam_max_fragmento;
	u_int16_t longitud_total;
	uint8_t tiempo_de_vida = 128;
	uint8_t ver_ihl = 0x45;
	uint8_t IP_origen[IP_ALEN];
	uint8_t protocolo_superior=pila_protocolos[0];
	uint8_t protocolo_inferior=pila_protocolos[2];
	uint8_t mascara[IP_ALEN], IP_rango_origen[IP_ALEN], IP_rango_destino[IP_ALEN];
	uint8_t gatewayIP[IP_ALEN];
	uint16_t aux16;
	idenfiticador++;
	printf("modulo IP(%"PRIu16") %s %d.\n",protocolo_inferior,__FILE__,__LINE__);

	Parametros ipdatos=*((Parametros*)parametros);
	uint8_t* IP_destino=ipdatos.IP_destino;

	obtenerIPInterface(interface, IP_origen);
	obtenerMascaraInterface(interface, mascara);
	aplicarMascara(IP_destino, mascara, IP_ALEN, IP_rango_destino);
	aplicarMascara(IP_origen, mascara, IP_ALEN, IP_rango_origen);
	
	if((*((uint32_t*)IP_rango_destino)) == (*((uint32_t*)IP_rango_origen))){
		if(solicitudARP(interface, IP_destino, ((Parametros*)parametros)->ETH_destino) == ERROR){
			return ERROR;
		}
	}else{
		if(obtenerGateway(interface, gatewayIP) == ERROR){
			return ERROR;
		}

		if(solicitudARP(interface, gatewayIP, ((Parametros*)parametros)->ETH_destino) == ERROR){
			return ERROR;
		}
	}

	mtu_ip = MTU - 20;

	num_fragmentos = ceil(longitud / (float) mtu_ip);
	tam_max_fragmento = mtu_ip;

	if(num_fragmentos > 1 && ipdatos.bit_DF == 1){
		printf("Bit df a 1 pero me llegan varios fragmentos\n");
		return ERROR;
	}


	memcpy(datagrama, &ver_ihl, sizeof(u_int8_t));
	memcpy(datagrama + 4, &idenfiticador, sizeof(u_int16_t));
	memcpy(datagrama + 8, &tiempo_de_vida, sizeof(u_int8_t));

	printf("ProtocolO = %d\n", protocolo_superior);
	memcpy(datagrama + 9, &protocolo_superior, sizeof(u_int8_t));
	memcpy(datagrama + 12, IP_origen, IP_ALEN);
	memcpy(datagrama + 16, IP_destino, IP_ALEN);

	
	// si hay solo un fragmento
	if(num_fragmentos == 1){
		memcpy(datagrama + 20, segmento, longitud);
		
		if(ipdatos.bit_DF == 1)
			flags_y_pos = htons(0x4000);
		memcpy(datagrama + 6, &flags_y_pos, sizeof(u_int16_t));
		
		longitud_total = htons(20 + longitud);
		memcpy(datagrama + 2, &longitud_total, sizeof(u_int16_t));
		
		calcularChecksum(datagrama, 20, (u_int8_t*)(&checksum));
		memcpy(datagrama + 10, &checksum, sizeof(u_int16_t));
		
		return protocolos_registrados[protocolo_inferior](datagrama, 20+longitud, pila_protocolos, parametros);
	}else{
		//Redondeamos al multiplo de 8 más cercano
		tam_max_fragmento = (tam_max_fragmento >> 3) << 3;

		num_fragmentos = ceil(longitud / (float) tam_max_fragmento);
		u_int16_t posicion = 0;

		for(int i = 0; i < num_fragmentos; i++){
			memset(datagrama + 10, 0, sizeof(u_int16_t));
			if(i != num_fragmentos - 1){
				longitud_total = 20 + tam_max_fragmento;
				aux16 = htons(longitud_total); 
				memcpy(datagrama + 20, segmento + i * tam_max_fragmento, tam_max_fragmento);
				flags = 0x2000;
			}else{
				longitud_total = 20 + longitud - i * tam_max_fragmento;
				aux16 = htons(longitud_total);
				memcpy(datagrama + 20, segmento + i * tam_max_fragmento, longitud - i * tam_max_fragmento);
				flags = 0;
			}
			
			flags_y_pos = htons(flags | (posicion / 8));
			memcpy(datagrama + 6, &flags_y_pos, sizeof(u_int16_t));
			
			memcpy(datagrama + 2, &aux16, sizeof(u_int16_t));
			
			calcularChecksum(datagrama, 20, (u_int8_t*)(&checksum));
			memcpy(datagrama + 10, &checksum, sizeof(u_int16_t));

			posicion += tam_max_fragmento;	
			if(protocolos_registrados[protocolo_inferior](datagrama, longitud_total, pila_protocolos, parametros) == ERROR){
				return ERROR;
			}
		}
		return OK;
	}
	
}


/****************************************************************************************
 * Nombre: moduloETH                                                                    *
 * Descripcion: Esta funcion implementa el modulo de envio Ethernet                     *
 * Argumentos:                                                                          *
 *  -datagrama: datagrama a enviar                                                      *
 *  -longitud: bytes que componen el datagrama                                          *
 *  -pila_protocolos: conjunto de protocolos a seguir                                   *
 *  -parametros: Parametros necesario para el envio este protocolo                      *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

#include <sys/time.h>
uint8_t moduloETH(uint8_t* datagrama, uint32_t longitud, __attribute__ ((unused)) uint16_t* pila_protocolos,void *parametros){
	uint8_t trama[ETH_FRAME_MAX]={0};
	uint8_t eth_origen[ETH_HLEN];
	uint16_t eth_type;
	struct pcap_pkthdr cabecera;
	cabecera.caplen = longitud + ETH_HLEN;
	cabecera.len = longitud + ETH_HLEN;
	
	gettimeofday(&cabecera.ts, NULL);

	printf("modulo ETH(fisica) %s %d.\n",__FILE__,__LINE__);

	if (longitud>MTU){
		return ERROR;
	}

	if(obtenerMACdeInterface(interface, eth_origen)==ERROR){
		printf("ERROR obteniendo mac origen");
		return ERROR;
	}

	memcpy(trama, ((Parametros*)parametros)->ETH_destino, ETH_HLEN);
	memcpy(trama+6, eth_origen, ETH_HLEN);
	eth_type = htons(0x0800);
	memcpy(trama+12, &eth_type, sizeof(uint16_t));
	memcpy(trama + 14, datagrama, longitud);

	pcap_dump((uint8_t*)pdumper, &cabecera,trama);
	pcap_inject(descr,trama,longitud+14);

	if(flag_mostrar){
		mostrarHex(trama, longitud + ETH_HLEN);
	}

	return OK;
}



/***************************Funciones auxiliares a implementar***********************************/

/****************************************************************************************
 * Nombre: aplicarMascara                                                               *
 * Descripcion: Esta funcion aplica una mascara a una vector                            *
 * Argumentos:                                                                          *
 *  -IP: IP a la que aplicar la mascara en orden de red                                 *
 *  -mascara: mascara a aplicar en orden de red                                         *
 *  -longitud: bytes que componen la direccion (IPv4 == 4)                              *
 *  -resultado: Resultados de aplicar mascara en IP en orden red                        *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t aplicarMascara(uint8_t* IP, uint8_t* mascara, uint8_t longitud, uint8_t* resultado){
	for(int i = 0; i < longitud; i++){
		resultado[i] = IP[i] & mascara[i];
	}
	return OK;
}


/***************************Funciones auxiliares implementadas**************************************/

/****************************************************************************************
 * Nombre: mostrarHex                                                                   *
 * Descripcion: Esta funcion imprime por pantalla en hexadecimal un vector              *
 * Argumentos:                                                                          *
 *  -datos: bytes que conforman un mensaje                                              *
 *  -longitud: Bytes que componen el mensaje                                            *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t mostrarHex(uint8_t * datos, uint32_t longitud){
	uint32_t i;
	printf("Datos:\n");
	for (i=0;i<longitud;i++){
		printf("%02"PRIx8" ", datos[i]);
	}
	printf("\n");
	return OK;
}


/****************************************************************************************
 * Nombre: calcularChecksum                                                             *
 * Descripcion: Esta funcion devuelve el ckecksum tal como lo calcula IP/ICMP           *
 * Argumentos:                                                                          *
 *   -datos: datos sobre los que calcular el checksum                                   *
 *   -longitud: numero de bytes de los datos sobre los que calcular el checksum         *
 *   -checksum: checksum de los datos (2 bytes) en orden de red!                        *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t calcularChecksum(uint8_t *datos, uint16_t longitud, uint8_t *checksum) {
    uint16_t word16;
    uint32_t sum=0;
    int i;
    // make 16 bit words out of every two adjacent 8 bit words in the packet
    // and add them up
    for (i=0; i<longitud; i=i+2){
        word16 = (datos[i]<<8) + datos[i+1];
        sum += (uint32_t)word16;       
    }
    // take only 16 bits out of the 32 bit sum and add up the carries
    while (sum>>16) {
        sum = (sum & 0xFFFF)+(sum >> 16);
    }
    // one's complement the result
    sum = ~sum;      
    checksum[0] = sum >> 8;
    checksum[1] = sum & 0xFF;
    return OK;
}


/***************************Funciones inicializacion implementadas*********************************/

/****************************************************************************************
 * Nombre: inicializarPilaEnviar                                                        *
 * Descripcion: inicializar la pila de red para enviar registrando los distintos modulos*
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/
uint8_t inicializarPilaEnviar() {
	bzero(protocolos_registrados,MAX_PROTOCOL*sizeof(pf_notificacion));
	if(registrarProtocolo(ETH_PROTO, moduloETH, protocolos_registrados)==ERROR)
		return ERROR;
	if(registrarProtocolo(IP_PROTO, moduloIP, protocolos_registrados)==ERROR)
		return ERROR;
	if(registrarProtocolo(UDP_PROTO, moduloUDP, protocolos_registrados)==ERROR)
		return ERROR;
	if(registrarProtocolo(ICMP_PROTO, moduloICMP, protocolos_registrados)==ERROR)
		return ERROR;
	
	return OK;
}


/****************************************************************************************
 * Nombre: registrarProtocolo                                                           *
 * Descripcion: Registra un protocolo en la tabla de protocolos                         *
 * Argumentos:                                                                          *
 *  -protocolo: Referencia del protocolo (ver RFC 1700)                                 *
 *  -handleModule: Funcion a llamar con los datos a enviar                              *
 *  -protocolos_registrados: vector de funciones registradas                            *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t registrarProtocolo(uint16_t protocolo, pf_notificacion handleModule, pf_notificacion* protocolos_registrados){
	if(protocolos_registrados==NULL ||  handleModule==NULL){		
		printf("Error: registrarProtocolo(): entradas nulas.\n");
		return ERROR;
	}
	else
		protocolos_registrados[protocolo]=handleModule;
	return OK;
}


