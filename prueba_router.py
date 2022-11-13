import socket
import sys

client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
_, headers, router_ip, router_port = sys.argv
FILE_PATH = "file.txt"

with open(FILE_PATH) as file:
    lines = file.readlines()
    for line in lines:
        message_content = headers + "," + line
        client_socket.sendto(message_content.encode(), (router_ip, int(router_port)))
        print('Mensaje enviado correctamente')
        print('Contenido del mensaje: ')
        print(message_content)
        print('enviado a: ', (router_ip, router_port), end="\n")
        
client_socket.close()
print('Conexion Terminada')