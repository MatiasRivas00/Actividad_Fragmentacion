import socket

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
        self.received_fragments = {} # id: list_of_fragments

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
        packet, _ = self.router_socket.recvfrom(1024)
        ip, port, ttl, *_, message = self.parse_packet(packet.decode())

        if not ttl > 0:
            print(f"Se recibió paquete {packet.decode()} con TTL {ttl}")
            return
        
        if (ip, port) == (self.ip, self.port):
            id = self.add_received_fragment(packet.decode())
            message = self.reassemple_ip_packet(self.received_fragments[id])
            if message is not None:
                print(f"message recieve: {message}")
            return
        
        next_router_address, mtu = self.check_route(ip, port)

        if next_router_address is not None:
            packet_fragments = self.fragment_ip_packet(packet, mtu)
            for packet_fragment in packet_fragments:
                self.router_socket.sendto(packet_fragment.encode(), next_router_address)

                print(f"redirigiendo paquete |||{packet_fragment}||| con destino final {ip, port} desde {self.ip, self.port} hacia {next_router_address}")

        else:
            print(f"No hay rutas hacia {ip, port} para paquete {packet.decode()}")
        
    def parse_packet(self, packet: str):
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

    def create_packet(self, args: tuple):
        """
        Create IP,port,message package format

        Parameters:
            args: tuple (ip,port,ttl,id,offset,size,flag,message) format
        Return:
            str: "ip,port,ttl,id,offset,size,flag,message"
        """
        ip, port, ttl, id, offset, size, flag, message = args
        size_zeros = "0"*(8 - len(str(size)))
        offset_zeros = "0"*(8 - len(str(offset)))
        return f"{ip},{port},{ttl},{id},{offset_zeros}{offset},{size_zeros}{size},{flag},{message}"

    def fragment_ip_packet(self, ip_packet: bytearray, mtu):
        """
        Fragment a ip packet if the message is too big to be send by the next
        router channel

        Parameters:
            ip_packet: "ip,port,ttl,id,offset,size,flag,message"
            mtu: bytes that support the channel
        Return:
            list_of_fragments: list of the fragments
        """
        if len(ip_packet) <= mtu:
            return [ip_packet.decode()]

        ip, port, ttl, id, offset, size, flag, message = self.parse_packet(ip_packet.decode())
        headers = self.create_packet((ip, port, ttl, id, offset, size, flag,"")) # empty message with headers
        headers_size = len(headers)
        message_max_size = mtu - headers_size 
        encoded_message = message.encode()
        packet_fragments = []

        for _from in range(0, size, message_max_size):
            to = min(_from + message_max_size, size)
            fragment_message = encoded_message[_from:to].decode()
            fragment_flag = int(bool(flag) or to!=size)
            fragment_size = len(fragment_message)
            fragment_offset = offset + _from

            packet_fragment = self.create_packet((ip, port, ttl - 1, id, fragment_offset, fragment_size, fragment_flag, fragment_message))
            packet_fragments.append(packet_fragment)
        
        return packet_fragments

    def reassemple_ip_packet(self, packet_fragments: list):
        """
        reassemble an ip packet guided by the offset

        Parameters:
            packet_fragments: fragments with the same id
        Return:
            message: message or None(incomplete fragments)
        """
        curr_offset = 0
        final_message = ""
        
        for packet_fragment in packet_fragments:
            _, _, _, id, offset, size, flag, message = self.parse_packet(packet_fragment)
            if curr_offset == offset:
                final_message += message
                curr_offset += size
            else:
                return
            if not bool(flag): # no quedan mensajes por recibir
                self.received_fragments[id] = []
                return final_message

    def add_received_fragment(self, packet_fragment: str):
        """
        add received fragment to the router cache and keeps
        sorted by offset

        Parameters:
            packet_fragment: a packet fragment
        Return:
            id: id of the received packet fragment
        """
        def get_offset(ip_packet):
            _, _, _, _, offset, *_ = self.parse_packet(packet_fragment)
            return int(offset)
        
        _, _, _, id, *_ = self.parse_packet(packet_fragment)
        if id in self.received_fragments:
            self.received_fragments[id].append(packet_fragment)
            self.received_fragments[id] = sorted(self.received_fragments[id], key=get_offset)
        else:
            self.received_fragments[id] = [packet_fragment]
        
        return id