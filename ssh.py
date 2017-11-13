"""
SSH reimplementation in Python, made by Unazed Spectaculum under the MIT license
"""

import socket
import struct


class SSH(object):
    """
    Abstracted interface for secure-shell protocol with underlying TCP structure
    """

    def __init__(self, host_ip, hostname, host_port=22, version="SSH-2.0"):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((host_ip, host_port))
        self.version = version
        self.hostname = hostname
        self.qualified_name = "%s-%s\r\n" % (version, hostname)

    def listen(self, backlog=1):
        self.socket.listen(backlog)

    def accept(self):
        while 1:
            client, info = self.socket.accept()
            print("{*} %s connected." % info[0])
            yield (client, info)
            print("{*} %s disconnected." % info[0])
            client.close()

    def handle_connections(self):
        for client, info in self.accept():
            version_info = client.recv(128)
            print("{*} Version Information: %s" % repr(version_info))

            if not version_info.startswith(self.version):
                print("{*} Client has incompatible versions.")
                continue

            client.send(self.qualified_name)

            pkt_len, pdn_len, payload, _ = self.binary_packet_parse(client)
            data = self.kexinit_packet_parse(payload, client)

    @staticmethod
    def kexinit_packet_parse(payload, sock):
        SSH_MSG_KEXINIT = payload[0]
        COOKIE = payload[1:17]
        PAYLOAD = payload[17:]

        KEX_ALGORITHMS_LENGTH = struct.unpack("!l", PAYLOAD[:4])[0]
        KEX_ALGORITHMS = PAYLOAD[4:4+KEX_ALGORITHMS_LENGTH]
        PAYLOAD = PAYLOAD[4+KEX_ALGORITHMS_LENGTH:]

        SERVER_HOST_KEY_ALGORITHMS_LENGTH = struct.unpack("!l", PAYLOAD[:4])[0]
        SERVER_HOST_KEY_ALGORITHMS = PAYLOAD[4:4+SERVER_HOST_KEY_ALGORITHMS_LENGTH].split(',')
        PAYLOAD = PAYLOAD[4+SERVER_HOST_KEY_ALGORITHMS_LENGTH:]

        ENCRYPTION_ALGORITHMS_CLIENT_TO_SERVER_LENGTH = struct.unpack("!l", PAYLOAD[:4])[0]
        ENCRYPTION_ALGORITHMS_CLIENT_TO_SERVER = PAYLOAD[4:4+ENCRYPTION_ALGORITHMS_CLIENT_TO_SERVER_LENGTH].split(',')
        PAYLOAD = PAYLOAD[4+ENCRYPTION_ALGORITHMS_CLIENT_TO_SERVER_LENGTH:]

        ENCRYPTION_ALGORITHMS_SERVER_TO_CLIENT_LENGTH = struct.unpack("!l", PAYLOAD[:4])[0]
        ENCRYPTION_ALGORITHMS_SERVER_TO_CLIENT = PAYLOAD[4:4+ENCRYPTION_ALGORITHMS_SERVER_TO_CLIENT_LENGTH].split(',')
        PAYLOAD = PAYLOAD[4+ENCRYPTION_ALGORITHMS_SERVER_TO_CLIENT_LENGTH:]

        MAC_ALGORITHMS_CLIENT_TO_SERVER_LENGTH = struct.unpack("!l", PAYLOAD[:4])[0]
        MAC_ALGORITHMS_CLIENT_TO_SERVER = PAYLOAD[4:4+MAC_ALGORITHMS_CLIENT_TO_SERVER_LENGTH].split(',')
        PAYLOAD = PAYLOAD[4+MAC_ALGORITHMS_CLIENT_TO_SERVER_LENGTH:]

        MAC_ALGORITHMS_SERVER_TO_CLIENT_LENGTH = struct.unpack("!l", PAYLOAD[:4])[0]
        MAC_ALGORITHMS_SERVER_TO_CLIENT = PAYLOAD[4:4+MAC_ALGORITHMS_SERVER_TO_CLIENT_LENGTH].split(',')
        PAYLOAD = PAYLOAD[4+MAC_ALGORITHMS_SERVER_TO_CLIENT_LENGTH:]

        COMPRESSION_ALGORITHMS_CLIENT_TO_SERVER_LENGTH = struct.unpack("!l", PAYLOAD[:4])[0]
        COMPRESSION_ALGORITHMS_CLIENT_TO_SERVER = PAYLOAD[4:4+COMPRESSION_ALGORITHMS_CLIENT_TO_SERVER_LENGTH].split(',')
        PAYLOAD = PAYLOAD[4+COMPRESSION_ALGORITHMS_CLIENT_TO_SERVER_LENGTH:]

        COMPRESSION_ALGORITHMS_SERVER_TO_CLIENT_LENGTH = struct.unpack("!l", PAYLOAD[:4])[0]
        COMPRESSION_ALGORITHMS_SERVER_TO_CLIENT = PAYLOAD[4:4+COMPRESSION_ALGORITHMS_SERVER_TO_CLIENT_LENGTH].split(',')
        PAYLOAD = PAYLOAD[4+COMPRESSION_ALGORITHMS_SERVER_TO_CLIENT_LENGTH:]

        LANGUAGES_CLIENT_TO_SERVER_LENGTH = struct.unpack("!l", PAYLOAD[:4])[0]
        LANGUAGES_CLIENT_TO_SERVER = PAYLOAD[4:4+LANGUAGES_CLIENT_TO_SERVER_LENGTH].split(',')
        PAYLOAD = PAYLOAD[4+LANGUAGES_CLIENT_TO_SERVER_LENGTH:]

        LANGUAGES_SERVER_TO_CLIENT_LENGTH = struct.unpack("!l", PAYLOAD[:4])[0]
        LANGUAGES_SERVER_TO_CLIENT = PAYLOAD[4:4+LANGUAGES_SERVER_TO_CLIENT_LENGTH].split(',')
        PAYLOAD = PAYLOAD[4+LANGUAGES_SERVER_TO_CLIENT_LENGTH:]

        FIRST_KEX_PACKET_FOLLOWS = bool(PAYLOAD[0])
        PAYLOAD = PAYLOAD[1:]

        RESERVED = struct.unpack("!l", PAYLOAD)

        print("{*} SSH_MSG_KEXINIT = %r" % SSH_MSG_KEXINIT)
        print("{*} Cookie = %r" % COOKIE)
        print("{*} KEX_ALGORITHMS = %s" % KEX_ALGORITHMS)
        print("{*} SERVER_HOST_KEY_ALGORITHMS = %s" % SERVER_HOST_KEY_ALGORITHMS)
        print("{*} ENCRYPTION_ALGORITHMS_CLIENT_TO_SERVER = %s" % ENCRYPTION_ALGORITHMS_CLIENT_TO_SERVER)
        print("{*} ENCRYPTION_ALGORITHMS_SERVER_TO_CLIENT = %s" % ENCRYPTION_ALGORITHMS_SERVER_TO_CLIENT)
        print("{*} MAC_ALGORITHMS_CLIENT_TO_SERVER = %s" % MAC_ALGORITHMS_CLIENT_TO_SERVER)
        print("{*} MAC_ALGORITHMS_SERVER_TO_CLIENT = %s" % MAC_ALGORITHMS_SERVER_TO_CLIENT)
        print("{*} COMPRESSION_ALGORITHMS_CLIENT_TO_SERVER = %s" % COMPRESSION_ALGORITHMS_CLIENT_TO_SERVER)
        print("{*} COMPRESSION_ALGORITHMS_SERVER_TO_CLIENT = %s" % COMPRESSION_ALGORITHMS_SERVER_TO_CLIENT)
        print("{*} LANGUAGES_CLIENT_TO_SERVER = %s" % LANGUAGES_CLIENT_TO_SERVER)
        print("{*} LANGUAGES_SERVER_TO_CLIENT = %s" % LANGUAGES_SERVER_TO_CLIENT)
        print("{*} FIRST_KEX_PACKETS_FOLLOWS = %r" % FIRST_KEX_PACKET_FOLLOWS)
        print("{*} RESERVED = %r" % RESERVED)

        if FIRST_KEX_PACKET_FOLLOWS:
            print("{*} Data = %r" % sock.recv(350000))

        return (
            SSH_MSG_KEXINIT,
            COOKIE,
            KEX_ALGORITHMS,
            SERVER_HOST_KEY_ALGORITHMS,
            ENCRYPTION_ALGORITHMS_CLIENT_TO_SERVER,
            ENCRYPTION_ALGORITHMS_SERVER_TO_CLIENT,
            MAC_ALGORITHMS_CLIENT_TO_SERVER,
            MAC_ALGORITHMS_SERVER_TO_CLIENT,
            COMPRESSION_ALGORITHMS_CLIENT_TO_SERVER,
            COMPRESSION_ALGORITHMS_SERVER_TO_CLIENT,
            LANGUAGES_CLIENT_TO_SERVER,
            LANGUAGES_SERVER_TO_CLIENT,
            FIRST_KEX_PACKET_FOLLOWS,
            RESERVED  # for error checking
        )
            
    @staticmethod
    def namelist_create(lists):
        pass

    @staticmethod
    def binary_packet_create(data):
        PACKET_LENGTH = struct.pack("!l", len(data))
        print("{*} PACKET_LENGTH = %r" % PACKET_LENGTH)

    @staticmethod
    def binary_packet_parse(sock):
        PACKET_LENGTH = struct.unpack("!l", sock.recv(4))[0]
        PADDING_LENGTH = struct.unpack("!b", sock.recv(1))[0]
        PAYLOAD = sock.recv(PACKET_LENGTH-PADDING_LENGTH-1)
        RANDOM_PADDING = sock.recv(PADDING_LENGTH+1)

        print("{*} Packet length = %s" % PACKET_LENGTH)
        print("{*} Pading length = %s" % PADDING_LENGTH)
        print("{*} Padding = %r" % RANDOM_PADDING)

        return (PACKET_LENGTH, PADDING_LENGTH, PAYLOAD, RANDOM_PADDING)

    def close(self):
        self.socket.close()
