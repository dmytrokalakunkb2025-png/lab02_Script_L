import hashlib
import os
import re
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass

# Константи
ITERATIONS = 100000
SESSION_TIMEOUT_SEC = 900

class User:
    def __init__(self, username: str, email: str, role: str = "user", active: bool = True):
        self.username = username
        self.role = role
        self.active = active
        self.__password_hash = None
        self.__password_salt = None
        self.email = email  # Викликає setter з валідацією

    @property
    def email(self):
        return self._email

    @email.setter
    def email(self, value: str):
        # Локальна частина починається з літери, 3-64 символи, далі @ і доменне ім'я
        pattern = r"^[a-zA-Z][a-zA-Z0-9._-]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, value):
            raise ValueError("Неправильний формат email")
        self._email = value

    def set_password(self, password: str):
        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), self.__password_salt, ITERATIONS
        )

    def check_password(self, password: str) -> bool:
        if not self.__password_salt or not self.__password_hash:
            return False
        test_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), self.__password_salt, ITERATIONS
        )
        import hmac
        return hmac.compare_digest(self.__password_hash, test_hash)

    def deactivate(self):
        self.active = False

    def __str__(self):
        return f"User({self.username}, {self.email}, Role: {self.role}, Active: {self.active})"

class Admin(User):
    def __init__(self, username: str, email: str, active: bool = True, permissions=None):
        super().__init__(username, email, role="admin", active=active)
        self.permissions = set(permissions) if permissions else set()

    def grant_permission(self, permission: str):
        self.permissions.add(permission)

    def revoke_permission(self, permission: str):
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self):
        perms = ", ".join(self.permissions) if self.permissions else "None"
        return super().__str__() + f" [Permissions: {perms}]"

class Session:
    def __init__(self, ip: str):
        self.ip = ip
        self.login_time = datetime.now(timezone.utc)
        self.last_activity = self.login_time

    def touch(self):
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            return False
        delta = datetime.now(timezone.utc) - self.last_activity
        return delta <= timedelta(seconds=timeout_sec)

@dataclass
class AuditLogEntry:
    timestamp: datetime
    username: str
    action: str

class AuditLog:
    def __init__(self):
        self.records = []

    def add_log(self, username: str, action: str):
        self.records.append(AuditLogEntry(datetime.now(timezone.utc), username, action))

    def show_all(self):
        for record in self.records:
            print(f"[{record.timestamp.isoformat()}] {record.username}: {record.action}")

class UserAccount:
    def __init__(self, user: User, audit_log: AuditLog = None):
        self.user = user
        self.session = None
        self.audit_log = audit_log or AuditLog()

    def login(self, password: str, ip: str) -> bool:
        if not self.user.active:
            self.audit_log.add_log(self.user.username, "login_failure (inactive)")
            return False
        
        if self.user.check_password(password):
            self.session = Session(ip)
            self.audit_log.add_log(self.user.username, "login_success")
            return True
        else:
            self.audit_log.add_log(self.user.username, "login_failure (wrong password)")
            return False

    def is_authenticated(self) -> bool:
        if self.session and self.session.is_active(SESSION_TIMEOUT_SEC):
            self.session.touch()
            return True
        return False

    def logout(self):
        if self.session:
            self.session = None
            self.audit_log.add_log(self.user.username, "logout")

    def __getitem__(self, key):
        if key == "user":
            return self.user
        elif key == "session":
            return self.session
        elif key == "audit_log":
            return self.audit_log
        else:
            raise KeyError(f"Невідомий ключ: {key}")

    def __setitem__(self, key, value):
        if key == "user" and isinstance(value, User):
            self.user = value
        elif key == "session" and (isinstance(value, Session) or value is None):
            self.session = value
        elif key == "audit_log" and isinstance(value, AuditLog):
            self.audit_log = value
        else:
            raise TypeError("Неправильний тип значення або ключ")

if __name__ == "__main__":
    # Створюємо тестового користувача
    test_user = User(username="admin_dima", email="dima@example.com")
    
    # Виводимо результат на екран
    print("Програму запущено!")
    # ... інші команди теж з відступом