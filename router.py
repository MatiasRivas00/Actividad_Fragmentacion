import sys
from router_class import Router

def format(route):
    destination_ip, from_port, to_port, connection_ip, connection_port, mtu = tuple(route.strip().split(' '))
    return (destination_ip, int(from_port), int(to_port), connection_ip, int(connection_port), 0, mtu)


_, ip, port, path = sys.argv 

with open(path) as routes:
    table = [format(route) for route in routes]

print("Creando Router")
router = Router(ip, int(port), table)

print("Router Iniciado")
while True:
    print("Esperando Paquete")
    router.listen()
