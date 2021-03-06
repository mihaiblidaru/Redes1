## Funciones

* [x] moduloICMP
* [x] moduloUDP
* [x] moduloIP
* [x] moduloETH
* [x] aplicarMascara
* [x] inicializarPilaEnviar


## Criterios de evaluación
### Ejercicio: Entrega el día 13 de diciembre.

* [x] ICMP y echo/ping dentro de la red local: 15%
    - Se comprobará con Wireshark que el destino recibe la petición de ping y que el emisor recibe la respuesta, estando ambos dentro de una misma subred.
* [ ] ICMP y echo/ping en un equipo no adyacente: 15%
    - Se comprobará con Wireshark en dos equipos que el destino recibe la petición de ping y que el emisor recibe la respuesta.
    - Se comprobará que la formación de la pregunta (una por paquete) tipo ARP request sea la correcta. Es por tanto imprescindible que para ello se tenga en cuenta si la IP destino está o no dentro de la propia subred.
* [x] Formación correcta de un paquete UDP dentro de la red local: 15%.
    - La validación de campos se realizará empleando Wireshark.
* [ ] Envío y Recepción de un paquete UDP en un equipo no adyacente (externo a la LAN): 15%.
    - Se ejecutará Wireshark en un equipo receptor con IP pública y se comprobará la recepción y corrección del paquete.
    - Se comprobará que la formación de la pregunta (una por paquete) tipo ARP request sea la correcta. Es por tanto imprescindible que para ello se tenga en cuenta si la IP destino está  o no dentro de la propia subred.
* [ ] Envío y Recepción de paquetes UDP que hayan sufrido fragmentación: 20%.
    - Se comprobará con Wireshark que el destino recibe datos a nivel de aplicación significativamente mayores a la MTU Ethernet pero menores al MSS teórico de UDP.
    - En el caso de no implementar esta funcionalidad y NO comprobar si los datos superan la MTU del enlace antes de intentar transmitirlos será penalizado con un 5% adicional a la perdida de puntuación de correspondiente a este apartado.
* [ ] Implementación del bit DF: 10%
    - Se comprobará con Wireshark que los paquetes enviados llevan el flag de no fragmentar activado.
    - Si se superase la MTU del enlace, el programa debe devolver un error y no transmitir la trama.
* [X] Lectura de datos para paquetes UDP desde archivo: 5%
* [ ] Impresión de tramas enviadas por pantalla en hexadecimal: 5%
* [ ] Fichero leeme.txt no suficientemente explicado: -5%.
