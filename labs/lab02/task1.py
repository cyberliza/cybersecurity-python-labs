import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone

# Константи системи
SESSION_TIMEOUT_SEC = 900
PBKDF2_ITERATIONS = 100_000
EMAIL_REGEX = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9_.]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
)


class User:
    # збереженням пароля та валідацією email

    def __init__(
        self, username: str, email: str, role: str = "user", active: bool = True
    ):
        self.username = username
        self.email = email  # Викликає setter декоратора @property
        self.role = role
        self.active = active
        self.__password_hash: bytes = b""
        self.__password_salt: bytes = b""

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        if not EMAIL_REGEX.match(value):
            raise ValueError(f"Некоректний формат email: '{value}'")
        self._email = value

    def set_password(self, password: str) -> None:
        # Хешування пароля через PBKDF2 з випадковою сіллю
        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )

    def check_password(self, password: str) -> bool:
        # Перевірка пароля із захистом від атак за часом 
        if not self.__password_hash or not self.__password_salt:
            return False
        computed_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )
        return hmac.compare_digest(self.__password_hash, computed_hash)

    def deactivate(self) -> None:
        self.active = False

    def __str__(self) -> str:
        status = "Active" if self.active else "Inactive"
        return f"User({self.username}, Email: {self.email}, Role: {self.role}, Status: {status})"


class Admin(User):
    # Клас Адміністратора із керуванням правами (наслідування від User).

    def __init__(
        self,
        username: str,
        email: str,
        permissions: list[str] | set[str] | None = None,
        active: bool = True,
    ):
        super().__init__(
            username=username, email=email, role="admin", active=active
        )
        if permissions is None:
            self.permissions: set[str] = set()
        else:
            self.permissions = set(permissions)

    def grant_permission(self, permission: str) -> None:
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        base_str = super().__str__()
        perms = ", ".join(sorted(self.permissions)) or "None"
        return f"{base_str} | Permissions: [{perms}]"


class Session:
    # Клас для відстеження активної сесії користувача у часі 

    def __init__(self, ip: str):
        self.ip = ip
        now = datetime.now(timezone.utc)
        self.login_time = now
        self.last_activity = now

    def touch(self) -> None:
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            raise ValueError("timeout_sec повинен бути додатним числом.")
        now = datetime.now(timezone.utc)
        elapsed = (now - self.last_activity).total_seconds()
        return elapsed < timeout_sec


@dataclass
class LogEntry:
    # запис в журналі аудиту

    timestamp: datetime
    username: str
    action: str


class AuditLog:
    # Журнал подій безпеки

    def __init__(self):
        self._logs: list[LogEntry] = []

    def add_log(self, username: str, action: str) -> None:
        entry = LogEntry(
            timestamp=datetime.now(timezone.utc),
            username=username,
            action=action,
        )
        self._logs.append(entry)

    def show_all(self) -> None:
        print("\n=== Audit Log Entries ===")
        for log in self._logs:
            time_str = log.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
            print(f"[{time_str}] User: {log.username:<12} | Action: {log.action}")


class UserAccount:
    # Обліковий запис

    def __init__(self, user: User, audit_log: AuditLog | None = None):
        self.user = user
        self.session: Session | None = None
        self.audit_log = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        if username != self.user.username:
            self.audit_log.add_log(username, "login_failure (unknown user)")
            return False

        if not self.user.active:
            self.audit_log.add_log(username, "login_failure (account disabled)")
            return False

        if self.user.check_password(password):
            self.session = Session(ip=ip)
            self.session.touch()
            self.audit_log.add_log(username, "login_success")
            return True
        else:
            self.audit_log.add_log(username, "login_failure (invalid password)")
            return False

    def is_authenticated(self) -> bool:
        if self.session is None:
            return False
        return self.session.is_active(SESSION_TIMEOUT_SEC)

    def logout(self) -> None:
        if self.user:
            self.audit_log.add_log(self.user.username, "logout")
        self.session = None

    def __getitem__(self, key: str):
        allowed_keys = {
            "user": self.user,
            "email": self.user.email,
            "role": self.user.role,
            "active": self.user.active,
        }
        if key in ("__password_hash", "__password_salt", "password"):
            raise KeyError("Приватні дані пароля недоступні через ключі.")
        if key in allowed_keys:
            return allowed_keys[key]
        raise KeyError(f"Невідомий ключ: '{key}'")

    def __setitem__(self, key: str, value) -> None:
        if key == "email":
            if not isinstance(value, str):
                raise TypeError("Email повинен бути рядком.")
            self.user.email = value
        elif key == "active":
            if not isinstance(value, bool):
                raise TypeError("Атрибут active повинен бути bool.")
            self.user.active = value
        else:
            raise KeyError(f"Зміна ключа '{key}' заборонена або ключ невідомий.")