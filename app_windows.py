import socket
import select
from datetime import datetime
import time
import sys
from typing import List

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QListWidget, QTextEdit, QLineEdit, QPushButton, QLabel, QListWidgetItem
)
from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt, QSize

from models.chatSession import ChatSession
from models.peer import Peer
from models.message import Message
from network.discovery_packet import create_discovery_announce, parse_discovery_announce, is_discovery_packet
from network.leave_packet import create_leave_packet, is_leave_packet, parse_leave_packet
import signal
from utils.crypto_utils import decrypt_message, encrypt_message, serialize_public_key, get_or_create_keys, get_fingerprint
from startup_window import StartupWindow


def handle_sigint(signal, frame):
    print("[\u00d7] Interruption (Ctrl+C). Envoi du paquet LEAVE...")
    window.send_leave()
    sys.exit(0)

signal.signal(signal.SIGINT, handle_sigint)


BUFFER_SIZE = 4096
DISCOVERY_BROADCAST_IP = "255.255.255.255"
LOCAL_IP = "172.23.112.36"
DISCOVERY_BROADCAST_PORT = 5007
MSG_PORT = 46209
TIMEOUT = 20


class MessageInput(QLineEdit):
    def __init__(self, parent=None):
        super().__init__(parent)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Return or event.key() == Qt.Key.Key_Enter:
            self.parent().send_message()
        else:
            super().keyPressEvent(event)


class ChatApp(QWidget):
    def __init__(self, username: str, ip: str):
        super().__init__()
        self.setWindowTitle("P2P ChatApp")
        self.setGeometry(100, 100, 900, 600)

        self.username = username
        self.local_ip = ip

        self.peers: set[Peer] = set()
        self.chat_sessions: list[ChatSession] = []
        self.active_session = None
        self.active_peer = None

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.local_ip, MSG_PORT))
        self.server_socket.listen(5)
        self.server_socket.setblocking(False)

        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.bind((self.local_ip, DISCOVERY_BROADCAST_PORT))
        self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.udp_socket.setblocking(False)

        self.sockets_to_monitor = [self.server_socket, self.udp_socket]

        self.private_key_ed, self.public_key_ed, self.private_key_x, self.public_key_x = get_or_create_keys()
        self.public_key_ed_bytes = serialize_public_key(self.public_key_ed)
        self.public_key_x_bytes = serialize_public_key(self.public_key_x)

        self.initUI()
        self.init_timers()


    def initUI(self):
        self.setStyleSheet("font-family: Arial; background-color: #e8f5e9; color: black;")
        main_layout = QHBoxLayout(self)

        self.user_list = QListWidget()
        self.user_list.setFixedWidth(300)
        self.user_list.setStyleSheet("""
            QListWidget {
                background-color: #ffffff;
                border: none;
                padding: 10px;
                font-size: 16px;
                border-radius: 10px;
            }
            QListWidget::item {
                padding: 12px;
                margin-bottom: 8px;
                background-color: #f1f1f1;
                border-radius: 8px;
                font-weight: bold;
                color: black;
            }
            QListWidget::item:selected {
                border: none;
                background-color: #4db6ac;
                color: white;
            }
            QListWidget::item:hover {
                background-color: #b2dfdb;
            }
        """)
        self.user_list.itemClicked.connect(self.load_chat)
        main_layout.addWidget(self.user_list)

        chat_layout = QVBoxLayout()

        self.chat_header = QLabel("Sélectionnez un @Host")
        self.chat_header.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        self.chat_header.setStyleSheet("background-color: #1f294d; color: white; padding: 15px; border-radius: 10px;")
        self.chat_header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        chat_layout.addWidget(self.chat_header)

        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.chat_display.setStyleSheet("background-color: white; color: black; border-radius: 10px; padding: 15px; font-size: 16px;")
        chat_layout.addWidget(self.chat_display)

        input_layout = QHBoxLayout()
        self.message_input = MessageInput(self)
        self.message_input.setPlaceholderText("Écrivez un message...")
        self.message_input.setStyleSheet("background-color: white; color: black; border-radius: 10px; padding: 15px; font-size: 16px;")

        self.send_button = QPushButton("Envoyer")
        self.send_button.setStyleSheet("background-color: #1f294d; color: white; padding: 15px; border-radius: 10px; font-size: 16px;")
        self.send_button.clicked.connect(self.send_message)

        input_layout.addWidget(self.message_input)
        input_layout.addWidget(self.send_button)

        chat_layout.addLayout(input_layout)
        main_layout.addLayout(chat_layout)
        self.setLayout(main_layout)

    def init_timers(self):
        self.timer = QTimer()
        self.timer.timeout.connect(self.event_loop)
        self.timer.start(100)

        self.presence_timer = QTimer()
        self.presence_timer.timeout.connect(self.send_discovery)
        self.presence_timer.start(5000)


    def find_peer(self, ip: str):
        for peer in self.peers:
            if peer.ip_address == ip:
                return peer
        return None

    def find_session_by_fileno(self, fileno: int):
        for session in self.chat_sessions:
            if session.socket.fileno() == fileno:
                return session
        return None


    def populate_user_list(self):
        self.user_list.clear()
        for peer in self.peers:
            item = QListWidgetItem(f" {peer.peer_name}@{peer.ip_address}")
            item.setData(Qt.ItemDataRole.UserRole, peer)
            font = QFont()
            font.setBold(True)
            item.setFont(font)
            item.setSizeHint(QSize(280, 50))
            self.user_list.addItem(item)


    def update_user_list(self):
        current_item = self.user_list.currentItem()
        current_peer = current_item.data(Qt.ItemDataRole.UserRole) if current_item else None

        self.user_list.clear()

        for peer in sorted(self.peers, key=lambda p: p.peer_name.lower()):
            text = f" {peer.peer_name}@{peer.ip_address}"
            if peer.unread_messages > 0:
                text += f" [{peer.unread_messages}]"

            item = QListWidgetItem(text)
            item.setData(Qt.ItemDataRole.UserRole, peer)
            font = QFont()
            font.setBold(True)
            item.setFont(font)
            item.setSizeHint(QSize(280, 50))
            self.user_list.addItem(item)

            # Rétablir la sélection si l’item est toujours là
            if current_peer and peer.ip_address == current_peer.ip_address:
                self.user_list.setCurrentItem(item)


    def load_chat(self, item):
        peer = item.data(Qt.ItemDataRole.UserRole)
        self.active_peer = peer
        self.chat_display.clear()
        self.active_peer.unread_messages = 0
        self.update_user_list()
        self.chat_header.setText(f"Chat avec {peer.peer_name}")

        for session in self.chat_sessions:
            if session.peer.ip_address == peer.ip_address:
                self.active_session = session
                self.chat_display.setText("\n".join(session.get_history()))
                return

        self.active_session = None


    def event_loop(self):
        try:
            readable, _, _ = select.select(self.sockets_to_monitor, [], [], 0.01)

            for sock in readable:
                if sock == self.server_socket:
                    try:
                        client, addr = self.server_socket.accept()
                        client.setblocking(False)
                        self.sockets_to_monitor.append(client)

                        peer = self.find_peer(addr[0])
                        if peer is None:
                            peer = Peer("Unknown", addr[0], None, addr[1])
                            self.peers.add(peer)
                            self.update_user_list()
                        else:
                            peer.port = addr[1]
                            peer.last_seen = datetime.now()

                        print(f"[+] Nouvelle connexion de {addr[0]}:{addr[1]}")
                        session = ChatSession(peer, client)
                        self.chat_sessions.append(session)

                        if self.active_peer and self.active_peer.ip_address == peer.ip_address:
                            self.active_session = session
                    except Exception as e:
                        print(f"[Erreur accept] {e}")

                elif sock == self.udp_socket:
                    try:
                        data, addr = self.udp_socket.recvfrom(BUFFER_SIZE)
                        if is_discovery_packet(data):

                            if addr[0] == self.local_ip:
                                continue

                            result = parse_discovery_announce(data)
                            username = result['username']
                            ip = result['ip']
                            ed25519_pub = result['ed25519_public_key']
                            x25519_pub_bytes = result['x25519_public_key_bytes']

                            if ip == self.local_ip:
                                continue

                            peer = self.find_peer(ip)
                            if peer:
                                peer.last_seen = time.time()
                            else:
                                peer = Peer(username, ip, ed25519_pub, x25519_pub_bytes)
                                peer.last_seen = time.time()
                                self.peers.add(peer)
                                self.update_user_list()

                        elif is_leave_packet(data):
                            result = parse_leave_packet(data)
                            leaving_ip = result['ip']
                            peer = self.find_peer(leaving_ip)
                            if peer:
                                if self.active_peer and self.active_peer.ip_address == peer.ip_address:
                                    self.chat_display.clear()
                                    self.chat_header.setText("Sélectionnez un @Host")
                                    self.active_peer = None
                                    self.active_session = None

                                for session in list(self.chat_sessions):
                                    if session.peer.ip_address == peer.ip_address:
                                        if session.socket in self.sockets_to_monitor:
                                            self.sockets_to_monitor.remove(session.socket)
                                        session.socket.close()
                                        self.chat_sessions.remove(session)

                                self.peers.remove(peer)
                                self.update_user_list()
                    except Exception as e:
                        print(f"[UDP Error] {e}")

                else:
                    session = self.find_session_by_fileno(sock.fileno())
                    if session:
                        try:
                            data = sock.recv(BUFFER_SIZE)
                            if data:
                                try:
                                    message_text = decrypt_message(data, self.private_key_x, session.peer.ed25519_public_key)
                                except Exception as e:
                                    message_text = "[Message non vérifié !]"
                                message = Message(message_text, is_sent=False, sender=session.peer)
                                session.add_message(message)

                                if self.active_peer and self.active_session and self.active_session.peer.ip_address == session.peer.ip_address:
                                    self.chat_display.append(str(message))
                                else:
                                    session.peer.unread_messages += 1
                                    self.update_user_list()
                            else:
                                raise ConnectionResetError()
                        except (ConnectionResetError, ConnectionAbortedError, OSError) as e:
                            print(f"[!] Déconnexion brutale de {session.peer.peer_name} ({session.peer.ip_address})")
                            if sock in self.sockets_to_monitor:
                                self.sockets_to_monitor.remove(sock)
                            sock.close()
                            if session in self.chat_sessions:
                                self.chat_sessions.remove(session)
                        except Exception as e:
                            print(f"[Erreur réception] {e}")
        except Exception as e:
            print(f"[Erreur générale dans event_loop] {e}")

    def send_message(self):
        content = self.message_input.text().strip()
        if not content:
            return
        if not self.active_peer:
            self.message_input.clear()
            self.message_input.setFocus()
            return
        if self.active_session is None:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((self.active_peer.ip_address, MSG_PORT))
                sock.setblocking(False)
                self.sockets_to_monitor.append(sock)
                session = ChatSession(self.active_peer, sock)
                self.chat_sessions.append(session)
                self.active_session = session
            except Exception as e:
                print(f"[Erreur connexion vers {self.active_peer.peer_name}] {e}")
        message = Message(content, is_sent=True, sender=None)
        self.active_session.add_message(message)
        self.chat_display.append(str(message))
        encrypted = encrypt_message(content, self.active_peer.x25519_public_key_bytes, self.private_key_ed)
        try:
            self.active_session.socket.sendall(encrypted)
        except Exception as e:
            print(f"[Erreur envoi] {e}")
        self.message_input.clear()
        self.message_input.setFocus()

    def send_discovery(self):
        try:
            msg = create_discovery_announce(
                self.username,
                self.local_ip,
                self.public_key_ed_bytes,
                self.public_key_x_bytes,
                self.private_key_ed
            )
            self.udp_socket.sendto(msg, (DISCOVERY_BROADCAST_IP, DISCOVERY_BROADCAST_PORT))
        except Exception as e:
            print(f"[Broadcast Error] {e}")

    def send_leave(self):
        try:
            msg = create_leave_packet(self.local_ip, self.private_key_ed)
            self.udp_socket.sendto(msg, (DISCOVERY_BROADCAST_IP, DISCOVERY_BROADCAST_PORT))
        except Exception as e:
            print(f"[Leave Error] {e}")

    def closeEvent(self, event):
        print("[\u00d7] Fermeture de l'application. Envoi du paquet LEAVE...")
        self.send_leave()
        super().closeEvent(event)





if __name__ == "__main__":
    app = QApplication(sys.argv)

    startup = StartupWindow()
    startup.show()
    app.exec()

    if startup.username:
        ip_local = "172.23.112.1"

        window = ChatApp(username=startup.username, ip=ip_local)
        window.show()
        sys.exit(app.exec())
