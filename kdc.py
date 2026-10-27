import os
import sys
import threading        
import aes
from node import Channel, listen

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

class KDC:
    def __init__(self, port):
        self.port = port
        self.keys = {}
        self.ks_len = 16

    def generate_session_key(self):
        out = ""
        while len(out) < self.ks_len:
            for b in os.urandom(self.ks_len):
                if b < 248 and len(out) < self.ks_len:
                    out += ALPHABET[b % len(ALPHABET)]
        return out

    def serve(self):
        srv = listen(self.port)
        print(f"[KDC] listening di 0.0.0.0:{self.port}")
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=self.handle, args=(Channel(conn), addr), daemon=True).start()

    def handle(self, ch, addr):
        try:
            m1 = ch.expect(1)
            id_a, id_b, n1 = m1["id_a"], m1["id_b"], int(m1["n1"])
            print(f"\n[KDC] (1) dari {addr[0]}: IDA={id_a} IDB={id_b} N1={n1}")
            for ident in (id_a, id_b):
                if ident not in self.keys:
                    ch.send(step="error", reason=f"{ident} tidak terdaftar di KDC")
                    print(f"[KDC] ditolak: {ident} belum terdaftar")
                    return
            ks = self.generate_session_key()
            for_a = aes.encrypt(f"{ks}|{id_a}|{id_b}|{n1}", self.keys[id_a])
            for_b = aes.encrypt(f"{ks}|{id_a}", self.keys[id_b])
            ch.send(step=2, for_a=for_a, for_b=for_b)
            print(f"[KDC] Ks={ks}")
            print(f"[KDC] (2) E(Ka,..) = {for_a}")
            print(f"[KDC] (2) E(Kb,..) = {for_b}")
        except Exception as e:
            print(f"[KDC] error dari {addr[0]}: {e}")
        finally:
            ch.close()

    def console(self):
        print("Perintah: add <id> <key> | del <id> | list | kslen <16|24|32> | quit")
        while True:
            try:
                parts = input("kdc> ").split(maxsplit=2)
            except EOFError:
                return
            if not parts:
                continue
            cmd = parts[0].lower()
            try:
                if cmd == "add" and len(parts) == 3:
                    if "|" in parts[1]:
                        raise ValueError("ID tidak boleh mengandung '|'")
                    aes.check_key(parts[2])
                    self.keys[parts[1]] = parts[2]
                    print(f"master key {parts[1]} disimpan")
                elif cmd == "del" and len(parts) == 2:
                    self.keys.pop(parts[1], None)
                elif cmd == "list":
                    for ident, key in self.keys.items():
                        print(f"  {ident}: {key}")
                elif cmd == "kslen" and len(parts) == 2 and parts[1] in ("16", "24", "32"):
                    self.ks_len = int(parts[1])
                elif cmd == "quit":
                    return
                else:
                    print("perintah tidak dikenal")
            except ValueError as e:
                print("Error:", e)

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    kdc = KDC(port)
    threading.Thread(target=kdc.serve, daemon=True).start()
    kdc.console()