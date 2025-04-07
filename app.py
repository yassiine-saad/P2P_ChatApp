import socket
import select
import tkinter as tk
from tkinter import scrolledtext
from datetime import datetime
from typing import List
from crypto_utils import generate_keys, encrypt_message, decrypt_message, serialize_public_key, deserialize_public_key

PORT = 12345
BUFFER_SIZE = 4096
BROADCAST_IP = "255.255.255.255"
BROADCAST_PORT = 5007

private_key, public_key = generate_keys()
discovered_peers = set()
selected_peer = None
chat_messages = {}
active_connections = {}

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

LOCAL_IP = get_local_ip()

class User:
    def __init__(self, ip_address: str, port: int, public_key=None):
        self.ip_address = ip_address
        self.port = port
        self.public_key = public_key

class Message:
    def __init__(self, content: str, is_sent: bool, sender_ip: str = ""):
        self.content = content
        self.is_sent = is_sent
        self.sender_ip = sender_ip
        self.timestamp = datetime.now()

    def __str__(self):
        sender_info = "Moi" if self.is_sent else self.sender_ip
        return f"[{self.timestamp.strftime('%H:%M:%S')}] {sender_info}: {self.content}"

class Chat:
    def __init__(self, user: User):
        self.user = user
        self.messages: List[Message] = []

    def add_message(self, message: Message):
        self.messages.append(message)

    def get_history(self):
        return "\n".join(str(msg) for msg in self.messages)

# Sockets et epoll
epoll = select.epoll()
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind(("0.0.0.0", PORT))
server_socket.listen(5)
server_socket.setblocking(False)
epoll.register(server_socket.fileno(), select.EPOLLIN)

udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
udp_socket.bind(("", BROADCAST_PORT))
udp_socket.setblocking(False)
epoll.register(udp_socket.fileno(), select.EPOLLIN)

sockets = {server_socket.fileno(): server_socket, udp_socket.fileno(): udp_socket}
clients = {}

def event_loop():
    events = epoll.poll(0.1)
    for fileno, event in events:
        if fileno == server_socket.fileno():
            client, addr = server_socket.accept()
            client.setblocking(False)
            epoll.register(client.fileno(), select.EPOLLIN)
            sockets[client.fileno()] = client
            clients[client.fileno()] = addr[0]
        elif fileno == udp_socket.fileno():
            try:
                data, addr = udp_socket.recvfrom(BUFFER_SIZE)
                peer_ip = addr[0]

                if data.startswith(b'LEAVE|'):
                    _, ip = data.decode().split('|')
                    if ip in discovered_peers:
                        discovered_peers.remove(ip)
                        chat_messages.pop(ip, None)
                        def remove_from_listbox():
                            for i in range(peer_listbox.size()):
                                if peer_listbox.get(i) == ip:
                                    peer_listbox.delete(i)
                                    break
                        root.after(0, remove_from_listbox)
                elif peer_ip != LOCAL_IP and peer_ip not in discovered_peers:
                    parts = data.split(b'||')
                    if len(parts) == 2:
                        _, public_key_pem = parts
                        peer_public_key = deserialize_public_key(public_key_pem)

                        discovered_peers.add(peer_ip)
                        user = User(peer_ip, PORT, public_key=peer_public_key)
                        chat_messages[peer_ip] = Chat(user)

                        root.after(0, lambda: peer_listbox.insert(tk.END, peer_ip))
            except Exception as e:
                print(f"[!] Erreur UDP : {e}")
        elif event & select.EPOLLIN:
            client = sockets.get(fileno)
            if client:
                try:
                    encrypted_data = client.recv(BUFFER_SIZE)
                    if encrypted_data:
                        try:
                            message_content = decrypt_message(private_key, encrypted_data)
                        except Exception as e:
                            print(f"[!] Erreur déchiffrement : {e}")
                            message_content = "<Message non déchiffrable>"

                        peer_ip = clients.get(fileno)
                        if peer_ip:
                            if peer_ip not in chat_messages:
                                chat_messages[peer_ip] = Chat(User(peer_ip, PORT))
                            message = Message(message_content, is_sent=False, sender_ip=peer_ip)
                            chat_messages[peer_ip].add_message(message)
                            if selected_peer == peer_ip:
                                root.after(0, lambda: update_chat(peer_ip))
                    else:
                        epoll.unregister(fileno)
                        client.close()
                        sockets.pop(fileno, None)
                        clients.pop(fileno, None)
                except:
                    epoll.unregister(fileno)
                    client.close()
                    sockets.pop(fileno, None)
                    clients.pop(fileno, None)
    root.after(100, event_loop)

def send_message():
    global selected_peer
    if selected_peer:
        message_content = entry_field.get()
        if message_content:
            try:
                if selected_peer not in active_connections:
                    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client.connect((selected_peer, PORT))
                    client.setblocking(False)
                    active_connections[selected_peer] = client
                else:
                    client = active_connections[selected_peer]

                chat = chat_messages[selected_peer]
                peer_public_key = chat.user.public_key
                encrypted_data = encrypt_message(peer_public_key, message_content)

                client.send(encrypted_data)

                message = Message(message_content, is_sent=True)
                chat.add_message(message)
                root.after(0, lambda: update_chat(selected_peer))
                entry_field.delete(0, tk.END)

            except Exception as e:
                print(f"[!] Erreur d'envoi à {selected_peer}: {e}")
                if selected_peer in active_connections:
                    try:
                        active_connections[selected_peer].close()
                    except:
                        pass
                    del active_connections[selected_peer]

def select_peer(event):
    global selected_peer
    selected_index = peer_listbox.curselection()
    if selected_index:
        selected_peer = peer_listbox.get(selected_index)
        peer_label.config(text=f"Parler avec: {selected_peer}")
        root.after(0, lambda: update_chat(selected_peer))

def announce_presence():
    try:
        public_key_pem = serialize_public_key(public_key)
        message = f"DISCOVER|{LOCAL_IP}".encode() + b'||' + public_key_pem
        udp_socket.sendto(message, (BROADCAST_IP, BROADCAST_PORT))
    except Exception as e:
        print(f"[!] Erreur broadcast : {e}")
    root.after(5000, announce_presence)

def send_leave_message():
    try:
        message = f"LEAVE|{LOCAL_IP}".encode()
        udp_socket.sendto(message, (BROADCAST_IP, BROADCAST_PORT))
    except Exception as e:
        print(f"[!] Erreur envoi LEAVE: {e}")

def update_chat(peer_ip):
    chat_box.delete(1.0, tk.END)
    if peer_ip in chat_messages:
        chat_box.insert(tk.END, chat_messages[peer_ip].get_history())
    chat_box.yview(tk.END)

def on_closing():
    send_leave_message()
    try:
        epoll.close()
        server_socket.close()
        udp_socket.close()
        for conn in active_connections.values():
            try:
                conn.close()
            except:
                pass
    except:
        pass
    root.destroy()

# Interface Tkinter
root = tk.Tk()
root.title("Chat P2P LAN Sécurisé - Linux")

frame = tk.Frame(root)
frame.pack()

peer_listbox = tk.Listbox(frame, width=20, height=20)
peer_listbox.pack(side=tk.LEFT, fill=tk.Y)
peer_listbox.bind("<<ListboxSelect>>", select_peer)

chat_box = scrolledtext.ScrolledText(frame, width=50, height=20)
chat_box.pack(side=tk.RIGHT, fill=tk.BOTH)

peer_label = tk.Label(root, text="Sélectionnez un pair")
peer_label.pack()

entry_field = tk.Entry(root, width=40)
entry_field.pack()
entry_field.bind("<Return>", lambda event: send_message())

send_button = tk.Button(root, text="Envoyer", command=send_message)
send_button.pack()

root.protocol("WM_DELETE_WINDOW", on_closing)
root.after(100, event_loop)
root.after(200, announce_presence)
root.mainloop()
