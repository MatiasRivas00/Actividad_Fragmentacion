import socket

def parse_packet(packet: str):
    """
    Parse IP,port,message package format

    Parameters:
        packet: str in IP,port,message format
    Return:
        tuple: (ip,port,ttl,id,offset,size,flag,message)
    """
    ip, port, ttl, id, offset, size, flag, *message = tuple(packet.split(','))
    port, ttl, id, offset, size, flag = map(lambda x: int(x), (port, ttl, id, offset, size, flag))

    return (ip, port, ttl, id, offset, size, flag, ','.join(message))

def create_packet(args: tuple):
    """
    Create IP,port,message package format

    Parameters:
        args: tuple (ip,port,ttl,id,offset,size,flag,message) format
    Return:
        str: "ip,port,ttl,id,offset,size,flag,message"
    """
    ip, port, ttl, id, offset, size, flag, message = args
    return f"{ip},{port},{ttl},{id},{offset},{size},{flag},{message}"


class Router:
    def __init__(self, ip, port, table) -> None:
        """
        Class that represents a router

        Parameters:
            ip: router IP
            port: router port
            table: list of (destination_ip, from_port, to_port, connection_ip, connection_port) tuples
        Return:
            None
        """
        self.ip = ip
        self.port = port
        self.table = table

        self.router_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.router_socket.bind((ip, port))

    def check_route(self, ip, port):
        """
        Retrieve the next router address that handle the
        package sending to adress

        Parameters:
            address: IP,port
        Return:
            next_router_address: tuple (IP,port, mtu)
        """
        min = None #(idx, route, min)
        for index, route in enumerate(self.table):
            destination_ip, from_port, to_port, connection_ip, connection_port, uses_count, mtu = route

            if ip == destination_ip and port in range(from_port, to_port + 1):
                if min is None or min[2] > uses_count:
                    min = (index, route, uses_count)
        if min is not None:
            destination_ip, from_port, to_port, connection_ip, connection_port, uses_count, mtu = min[1]
            self.table[min[0]] = (destination_ip, from_port, to_port, connection_ip, connection_port, uses_count + 1, mtu)
            return (connection_ip, connection_port), mtu
    
    def listen(self):
        """
        Listen incoming udp messages

        Parameters:
            None
        Return:
            None
        """
        packet, sender = self.router_socket.recvfrom(1024)
        ip, port, ttl, id, offset, size, flag, message = parse_packet(packet.decode())

        if not ttl > 0:
            print(f"Se recibió paquete {packet.decode()} con TTL {ttl}")
            return
        
        if (ip, port) == (self.ip, self.port):
            print(f"message recieve: {message}")
            return
        
        next_router_address, mtu = self.check_route(ip, port)

        if next_router_address is not None:
            new_packet = create_packet((ip, port, ttl - 1, id, offset, size, flag, message))
            print(f"redirigiendo paquete |||{new_packet}||| con destino final {ip, port} desde {self.ip, self.port} hacia {next_router_address}")
            self.router_socket.sendto(new_packet.encode(), next_router_address)
        else:
            print(f"No hay rutas hacia {ip, port} para paquete {packet.decode()}")