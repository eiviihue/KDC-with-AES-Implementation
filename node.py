import json
import os
import socket
import sys
import threading
import aes

class Channel:
    def __init__(self, sock):
        self.sock = sock
        self.reader = sock.makefile("r", encoding="utf-8")

    @classmethod
    def connect(cls, host, port, timeout=10):
        sock = socket.create_connection((host, int(port)), timeout=timeout)
        sock.settimeout(None)
        return cls(sock)

    def send(self, **msg):
        self.sock.sendall((json.dumps(msg) + "\n").encode("utf-8"))

    def recv(self):
        line = self.reader.readline()
        if not line:
            raise ConnectionError("koneksi ditutup")
        return json.loads(line)

    def expect(self, step):
        msg = self.recv()
        if msg.get("step") == "error":
            raise ValueError(msg.get("reason", "error dari lawan"))
        if msg.get("step") != step:
            raise ValueError(f"menunggu langkah {step}, menerima {msg.get('step')}")
        return msg

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()

def listen(port, host="0.0.0.0"):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, int(port)))
    srv.listen()
    return srv

def make_nonce():
    return int.from_bytes(os.urandom(4), "big")

def f(n):
    return n + 1

class Session:
    def __init__(self, peer_id, ch, ks):
        self.peer_id = peer_id
        self.ch = ch
        self.ks = ks

class Node:
    def __init__(self, ident, port):
        self.id = ident
        self.port = port
        self.master_key = None
        self.kdc_addr = None
        self.last_target = None
        self.session = None

    def serve(self):
        srv = listen(self.port)
        print(f"[{self.id}] listening di 0.0.0.0:{self.port}")
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=self.respond, args=(Channel(conn), addr), daemon=True).start()

    def respond(self, ch, addr):
        try:
            if not self.master_key:
                raise ValueError("master key belum di-set")
            m3 = ch.expect(3)
            print(f"\n[{self.id}] (3) dari {addr[0]}: {m3['ticket']}")
            ks, id_a = aes.decrypt(m3["ticket"], self.master_key).split("|")
            print(f"[{self.id}] ticket valid: Ks={ks} IDA={id_a}")
            n2 = make_nonce()
            c4 = aes.encrypt(str(n2), ks)
            ch.send(step=4, data=c4)
            print(f"[{self.id}] (4) N2={n2} -> {c4}")
            m5 = ch.expect(5)
            got = int(aes.decrypt(m5["data"], ks))
            print(f"[{self.id}] (5) {m5['data']} -> f(N2)={got}")
            if got != f(n2):
                raise ValueError("f(N2) tidak cocok")
            self.start_session(Session(id_a, ch, ks))
        except Exception as e:
            print(f"[{self.id}] handshake dari {addr[0]} gagal: {e}")
            ch.close()

    def initiate(self, peer_id, host, port):
        if not self.master_key or not self.kdc_addr:
            raise ValueError("set /master dan /kdc dulu")
        n1 = make_nonce()
        kdc = Channel.connect(*self.kdc_addr)
        try:
            kdc.send(step=1, id_a=self.id, id_b=peer_id, n1=n1)
            print(f"[{self.id}] (1) IDA={self.id} IDB={peer_id} N1={n1}")
            m2 = kdc.expect(2)
        finally:
            kdc.close()
        print(f"[{self.id}] (2) E(Ka,..) = {m2['for_a']}")
        ks, id_a, id_b, n1_back = aes.decrypt(m2["for_a"], self.master_key).split("|")
        if id_a != self.id or id_b != peer_id or int(n1_back) != n1:
            raise ValueError("balasan KDC tidak cocok dengan request (replay?)")
        print(f"[{self.id}] Ks={ks}, N1 cocok")

        ch = Channel.connect(host, port)
        try:
            ch.send(step=3, ticket=m2["for_b"])
            print(f"[{self.id}] (3) ticket -> {peer_id}")
            m4 = ch.expect(4)
            n2 = int(aes.decrypt(m4["data"], ks))
            c5 = aes.encrypt(str(f(n2)), ks)
            ch.send(step=5, data=c5)
            print(f"[{self.id}] (4) N2={n2}, (5) f(N2)={f(n2)} -> {c5}")
        except Exception:
            ch.close()
            raise
        self.last_target = (peer_id, host, port)
        self.start_session(Session(peer_id, ch, ks))

    def start_session(self, sess):
        old, self.session = self.session, sess
        if old:
            old.ch.close()
        print(f"[{self.id}] sesi AES dengan {sess.peer_id} aktif (Ks={sess.ks})")
        threading.Thread(target=self.receive_loop, args=(sess,), daemon=True).start()

    def receive_loop(self, sess):
        try:
            while True:
                msg = sess.ch.recv()
                cipher = msg.get("data", "")
                try:
                    plain = aes.decrypt(cipher, sess.ks)
                except ValueError as e:
                    plain = f"<gagal dekripsi: {e}>"
                print(f"\n[{sess.peer_id}] cipher : {cipher}\n[{sess.peer_id}] plain  : {plain}")
        except (ConnectionError, OSError, ValueError):
            pass
        if self.session is sess:
            self.session = None
            print(f"\n[{self.id}] sesi dengan {sess.peer_id} berakhir")

    def send_text(self, text):
        sess = self.session
        if not sess:
            raise ValueError("belum ada sesi, gunakan /connect")
        cipher = aes.encrypt(text, sess.ks)
        sess.ch.send(step="msg", data=cipher)
        print(f"[{self.id} -> {sess.peer_id}] cipher : {cipher}")

    def console(self):
        print("Perintah: /master <key> | /kdc <ip> <port> | /connect <id> <ip> <port> | /rekey\n"
              "          /ks <key> | /info | /quit | teks lain = kirim pesan")
        while True:
            try:
                line = input()
            except EOFError:
                return
            if not line.strip():
                continue
            parts = line.split()
            cmd = parts[0].lower()
            try:
                if cmd == "/master" and len(parts) == 2:
                    aes.check_key(parts[1])
                    self.master_key = parts[1]
                    print("master key di-set")
                elif cmd == "/kdc" and len(parts) == 3:
                    self.kdc_addr = (parts[1], int(parts[2]))
                elif cmd == "/connect" and len(parts) == 4:
                    self.initiate(parts[1], parts[2], int(parts[3]))
                elif cmd == "/rekey":
                    if not self.last_target:
                        raise ValueError("belum pernah /connect")
                    self.initiate(*self.last_target)
                elif cmd == "/ks" and len(parts) == 2:
                    aes.check_key(parts[1])
                    if not self.session:
                        raise ValueError("belum ada sesi")
                    self.session.ks = parts[1]
                    print("session key lokal diganti")
                elif cmd == "/info":
                    s = self.session
                    print(f"ID={self.id} port={self.port} master={self.master_key} KDC={self.kdc_addr}")
                    print(f"sesi={s.peer_id if s else '-'} Ks={s.ks if s else '-'}")
                elif cmd == "/quit":
                    return
                elif cmd.startswith("/"):
                    print("perintah tidak dikenal / argumen salah")
                else:
                    self.send_text(line)
            except (ValueError, OSError) as e:
                print("Error:", e)

if __name__ == "__main__":
    ident = sys.argv[1] if len(sys.argv) > 1 else input("ID: ").strip()
    port = int(sys.argv[2]) if len(sys.argv) > 2 else int(input("Port listen: "))
    if not ident or "|" in ident:
        sys.exit("ID tidak valid")
    node = Node(ident, port)
    threading.Thread(target=node.serve, daemon=True).start()
    node.console()