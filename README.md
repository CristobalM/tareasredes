# tareasredes

## Supuestos:

* Consideramos que como al menos se tenian que aceptar mensajes del tipo A, AAAA, y MX y los demas opcionales, decidimos aceptar todos los mensajes que pasaran por el proxy.

* 

## Consideraciones


 En el archivo config.json se encuentran 3 llave:valor que sirven para manejar las direcciones de las consultas, uno para el hostname, otro para el resolver a donde se mandara la informacion,  y el ultimo para manejar el puerto del resolver

 El archivo filtros.json tiene 2 diccionarios:

 * ban: tiene todas las direcciones url que no procesara el proxy. Para agregar nuevos elementos se tienen que colocar entre comillas y separandolos con una coma.

 * redireccion: tiene las direcciones y las ip que deberia entregar cuando se realize dicha consulta. Para agregar nuevos elementos deben agregarse la tupla direccion-ip, separando por comas los elementos.

En ambos casos se agregan un par de ejemplos de como deberían agregarse los elementos a los archivos

## Correr la tarea
 Para correr la tarea se ocupa el comando 

´´´xml 
 sudo ~/.virtualenvs/tareasredes/bin/python3.6 tarea1_redes.py 53
´´´

 donde 53 es el puerto desde donde escucha las consultas el servidor, con sudo debido a que necesitamos permiso de administrador para poder usar ese puerto.
 



