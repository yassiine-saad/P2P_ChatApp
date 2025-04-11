# from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLineEdit, QLabel, QPushButton
# from PyQt6.QtGui import QFont
# from PyQt6.QtCore import Qt

# class StartupWindow(QWidget):
#     def __init__(self):
#         super().__init__()
#         self.setWindowTitle("Lancement du Chat")
#         self.setGeometry(500, 300, 400, 250)

#         self.setStyleSheet("""
#             QWidget {
#                 background-color: #f0f4f8;
#                 font-family: Arial;
#             }
#             QLabel {
#                 font-size: 15px;
#                 margin-bottom: 5px;
#             }
#             QLineEdit {
#                 font-size: 15px;
#                 padding: 10px;
#                 border: 1px solid #ccc;
#                 border-radius: 8px;
#                 background-color: #ffffff;
#             }
#             QPushButton {
#                 background-color: #1f294d;
#                 color: white;
#                 font-size: 16px;
#                 padding: 10px;
#                 border-radius: 10px;
#             }
#             QPushButton:hover {
#                 background-color: #394574;
#             }
#         """)

#         self.username = ""
#         self.selected_ip = ""

#         layout = QVBoxLayout()
#         layout.setContentsMargins(30, 30, 30, 30)
#         layout.setSpacing(15)

#         title = QLabel("Bienvenue dans le Chat")
#         title.setAlignment(Qt.AlignmentFlag.AlignCenter)
#         title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
#         layout.addWidget(title)

#         self.name_input = QLineEdit()
#         self.name_input.setPlaceholderText("Entrez votre Nom d'utilisateur")
#         layout.addWidget(QLabel("Nom d'utilisateur"))
#         layout.addWidget(self.name_input)

#         self.ip_input = QLineEdit()
#         self.ip_input.setPlaceholderText("Entrez votre adresse IP locale")
#         layout.addWidget(QLabel("Adresse IP locale"))
#         layout.addWidget(self.ip_input)

#         self.ok_button = QPushButton("Lancer le Chat")
#         self.ok_button.clicked.connect(self.on_ok)
#         layout.addWidget(self.ok_button)

#         self.setLayout(layout)

#     def on_ok(self):
#         name = self.name_input.text().strip()
#         ip = self.ip_input.text().strip()

#         if name and ip:
#             self.username = name
#             self.selected_ip = ip
#             self.close()
#         else:
#             print("[!] Veuillez remplir les deux champs.")

   





from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLineEdit, QLabel, QPushButton
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt

class StartupWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Lancement du Chat")
        self.setGeometry(500, 300, 400, 200)

        self.setStyleSheet("""
            QWidget {
                background-color: #f0f4f8;
                font-family: Arial;
            }
            QLabel {
                font-size: 15px;
                margin-bottom: 5px;
            }
            QLineEdit {
                font-size: 15px;
                padding: 10px;
                border: 1px solid #ccc;
                border-radius: 8px;
                background-color: #ffffff;
            }
            QPushButton {
                background-color: #1f294d;
                color: white;
                font-size: 16px;
                padding: 10px;
                border-radius: 10px;
            }
            QPushButton:hover {
                background-color: #394574;
            }
        """)

        self.username = ""

        layout = QVBoxLayout()
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(15)

        title = QLabel("Bienvenue dans le Chat")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        layout.addWidget(title)

        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Entrez votre Nom d'utilisateur")
        layout.addWidget(QLabel("Nom d'utilisateur"))
        layout.addWidget(self.name_input)

        self.ok_button = QPushButton("Lancer le Chat")
        self.ok_button.clicked.connect(self.on_ok)
        layout.addWidget(self.ok_button)

        self.setLayout(layout)

    def on_ok(self):
        name = self.name_input.text().strip()

        if name:
            self.username = name
            self.close()
        else:
            print("[!] Veuillez entrer un nom d'utilisateur.")
