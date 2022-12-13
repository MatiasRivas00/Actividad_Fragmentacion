# Simulación de Comunicación de Routers con Fragmentación (Simplificado)
La idea es usar sockets para poder conectar nuestros routers teóricos, cada router tiene acceso a una tabla de direcciones,
además del ancho de banda máximo de cada conexión en bytes, si el mensaje que recibe no está destinado para el router que lo recibe,
este revisa su tabla de direcciones para redireccionar el mensaje, en caso de no tener un camino válido se descarta el mensaje.
