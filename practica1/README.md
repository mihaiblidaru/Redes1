# Ejercicios
## Se pide la entrega de dos ejercicios:

## Primer ejercicio: libpcap

Se facilita un programa ejemplo en el Moodle. Descárguelo, analícelo y modifíquelo para que cumpla los requisitos definidos a continuación.

Entregue los fuentes C (*.c y *.h) y makefile usados para implementar un programa basado en libpcap que:     

1. Si se ejecuta sin argumentos, debe devolver ayuda de ejecución.
2. Si se ejecuta con un argumento, consideramos que queremos capturar de interfaz:
   1. El programa debe mostrar el número de paquetes recibidos por la interfaz de red eth0 tras pulsar Control-C.
   2. El programa debe almacenar los paquetes capturados enteros en una traza con nombre eth0.FECHA.pcap (donde FECHA será el tiempo actual UNIX en segundos).
   3. Al almacenar la traza queremos modificar la fecha de cada paquete capturado. La modificación consistirá en sumar 30 minutos a la fecha de captura. Ejemplo: si capturamos el día 20 de octubre a las 10:23, deberíamos observar en la traza almacenada los paquetes con fecha del 20 de octubre a las 10:53.
3. Si se ejecuta con dos argumentos (el segundo será la traza a analizar), consideramos que queremos analizar una traza pcap. El programa debe mostrar el número de paquetes de la traza al finalizar su ejecución.
En ambos casos (traza o captura de interfaz/en vivo) el programa debe mostrar los N (N es el primer argumento de ejecución) primeros bytes de cada paquete capturado/analizado en hexadecimal con 2 dígitos por Byte (y separando cada Byte por espacios en blanco). 
Prestad atención a los límites de bytes capturados, y a paquetes más pequeños (¿los hay?).
Para demostrar la corrección de este tercer apartado use Wireshark: compare visualmente si la salida de su programa coincide con la salida que da Wireshark en su ventana inferior. Se espera que no haya diferencias.
Haga una captura de pantalla que muestre ambas salidas para una captura en vivo (online). Llame a esta captura de pantalla practica1captura.*, e inclúyala en la entrega.
NOTA IMPORTANTE. El programa solo debe distinguir la fuente de entrada a la hora de abrir el descriptor: NO se debe por tanto hacer dos "hilos" distintos para cada tipo de operación sino tan solo un flujo que al principio distinga de donde "sale" el tráfico sobre el que trabajar pero, a partir de ese punto, debe haber un único flujo con las mínimas variaciones posibles.
Segundo ejercicio: Wireshark 

Responda al listado de preguntas en el documento "Ejercicios de captura de tráfico".

Criterios de evaluación
Ejercicios: Entrega antes de las 23:55 del 18 de octubre.

Normativa de entrega cumplida en su totalidad: 5%
Fichero leeme.txt bien explicado: 5%
Contar paquetes de una traza (independientemente del número de paquetes): 10%
Contar paquetes de la interfaz de red: 5%
Uso de un único "flujo" para traza e interfaz: 10%
Almacenar correctamente el tráfico capturado en vivo una traza: 10%
Modificar fecha correctamente: 15%
Imprimir los N primeros bytes de un paquete (pruebe para N>15) y validarlo con Wireshark (captura de pantalla): 20%
Ejercicios de captura de tráfico: 20%
Control individual: Cuestionario sobre manejo básico de Wireshark y libpcap el día 19 de octubre. No olvide ser puntual, el control empezará a "y 5".


Entrega

Respecto al ejercicio Libpcap, denomine a los archivos de entrega practica1.c y practica1.h.
Añada un archivo leeme.txt que incluya los nombres de los autores, comentarios que se quieran transmitir al profesor y, en caso de entregar algún archivo más, la descripción y/o explicación del mismo. Además este fichero debe contener una sección donde se determine si se ha dado respuesta (Realizado/Parcialmente-Realizado/No-Realizado, y en caso afirmativo la explicación de cómo se ha validado) a cada criterio de evaluación solicitado. Ejemplo:

Normativa de entrega cumplida en su totalidad: Realizado: Varias relecturas del enunciado.
Contar paquetes de una traza: Realizado: Se ha comprabado que el número de paquete que muestra nuestro programa coincide con el que indica Wireshark.
Contar paquetes de la interfaz de red: No-Realizado.
Almacenar en una traza el tráfico capturado en vivo: Realizado: Se ha comprabado que todos los bytes de la traza capturado coincide con lo que indica Wireshark en un conjunto diverso de paquetes.
Modificar fecha correctamente: No-Realizado.
Imprimir los N primeros bytes de un paquete y validarlo con Wireshark (captura de pantalla): Parcialmente-Realizado: Se imprimen correctamente solamente los 5 primeros bytes.
Cuestionario "Ejercicios de captura de tráfico": No-Realizado.
No olvide el makefile (en caso contrario no se corregirá la práctica) ni la captura de pantalla solicitada.
Respecto al ejercicio Wireshark, entregue un pdf con sus respuesta con nombre practica1.pdf. Debe ser un pdf, no se aceptará ningún otro formato. Adicionalmente añada la traza que haya generado para dar respuesta a las cuestiones, y llámela practica1.pcap.

Comprima en un zip TODO lo que vaya a entregar y llámelo practica1_YYYY_PXX.zip, donde YYYY es el grupo al que pertenece (1301,1302,etc), y XX (y solo XX) es el número de pareja (con dos dígitos).

Por ejemplo, para la pareja 5 del grupo 1301: $ zip practica1_1301_P05.zip *

Solo es necesario que suba la entrega un miembro de la pareja.

