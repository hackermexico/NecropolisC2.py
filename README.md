# ☠️ NecroPolisC2

**NecroPolisC2** es un servidor de Comando y Control (C2) ligero, escrito en Python puro, enfocado en simplicidad, modularidad y control total de agentes conectados mediante una shell TCP interactiva. Diseñado para prácticas de Red Team, automatización de pentests y ambientes controlados de ciberseguridad.

> 🕳️ “Desde las catacumbas digitales, el control renace…”

---

## ⚙️ Características

- ☠️ Shell interactiva para múltiples clientes
- 🔐 Autenticación por contraseña
- 💀 Selección y administración de clientes en tiempo real
- 👻 Comandos personalizados desde el servidor
- 🧠 Basado en clases y multithreading
- ⛓️ Modular y fácilmente extensible
- 🧩 Compatible con Linux (cliente y servidor)

---

## 📦 Requisitos

- Python 3.x
- Sistema basado en Unix (recomendado para el cliente)
- Acceso a red TCP entre cliente y servidor

---

## 🚀 Instalación y ejecución

### ▶️ Servidor C2

```bash
python3 NecropolisC2Server.py --host 0.0.0.0 --port 777 --password 1337

COMANDOS:

help                  - Mostrar ayuda
list                  - Listar clientes conectados
select <id>           - Seleccionar cliente por ID
disconnect <id>       - Desconectar cliente
exit                  - Salir del servidor
<any command>         - Enviar a cliente seleccionado

EJEMPLO de uso:

necropolisc2> list
1. 192.168.1.101:4096 [Alive]
necropolisc2> select 1
[+] Cliente '1' seleccionado: 192.168.1.101:4096
necropolisc2> whoami
root

⚠️ Advertencia
Este software es solo para fines educativos y pruebas en entornos controlados.
Ni el autor ni los colaboradores se hacen responsables del uso indebido de esta herramienta.

🧛‍♂️ Autor
🕷️ SaturniCipher — Hacker, mago digital y arquitecto de la oscuridad binaria.

🧠 Ideas para el futuro

Plugins para keylogger, persistence, screenshot

Soporte a cifrado por TLS

Autogenerador de payloads Linux/Windows

Interfaz web minimalista

