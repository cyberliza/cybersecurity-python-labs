import csv
from functools import wraps
import hashlib
import json
import sys
import os
from pathlib import Path
from datetime import datetime


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),'../../')))
from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER

class ValidationError(Exception):

    pass

hash_algorithm = "blake2b"
min_length = 12

DATA_DIR = Path(__file__).resolve().parent / "data"
CSV_FILE = DATA_DIR / "users.csv"
LOG_FILE = DATA_DIR / "log.json"


def generate_hash(password: str, salt: str= "00000") -> str:
    if not password or not salt:
        raise ValueError("Пароль та сіль породжні")
    if len(password) < min_length:
        raise ValidationError(
            f"Пароль коротший за мінімальну довжину ({min_length})"
        )

    data = (password + salt).encode("utf-8")
    h = hashlib.new(hash_algorithm)
    h.update(data)
    return h.hexdigest()

def create_user(username: str, password: str) -> tuple[str, str]:
    # Сіль із 5 символів, доповнена нулями 
    personal_salt = str(VARIANT_NUMBER).zfill(5)
    pass_hash = generate_hash(password, salt=personal_salt)
    return (username, pass_hash)


def create_users(users_list: list[tuple[str, str]]):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    records = []

    for un, pw in users_list:
        try:
            records.append(create_user(un, pw))
        except (ValueError, ValidationError) as e:
            print(f"[Помилка для {un}]: {e}")
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["username", "password_hash"])
            writer.writerows(records)
            f.flush()  # Примусово записати буфер на диск
    except (PermissionError, IOError) as e:
        print(f"[Помилка запису файлу CSV]: {e}")

def load_users_db() -> list[dict]: # зчитує вміст CSV-файлу у список users_db
    users_db = []
    if not CSV_FILE.exists():
        return users_db

    try:
        with open(CSV_FILE, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                users_db.append(row)
    except (PermissionError, IOError, csv.Error) as e:
        print(f"[Помилка читання файлу CSV]: {e}")

    return users_db

def log_event(func): # Декоратор для логування подій
    @wraps(func)
    def wrapper(*args, **kwargs):
        username = kwargs.get("username") or (args[0] if args else "unknown")
        result_status = "failure"

        try:
            res = func(*args, **kwargs)
            if res is True:
                result_status = "success"
            return res
        except Exception:
            result_status = "failure"
            raise
        finally:
            log_entry = {
                "event": func.__name__,
                "user": username,
                "result": result_status,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "args": list(args),
                "kwargs": kwargs,
            }

            DATA_DIR.mkdir(parents=True, exist_ok=True)

            logs = []
            if LOG_FILE.exists():
                try:
                    with open(LOG_FILE, "r", encoding="utf-8") as f:
                        logs = json.load(f)
                except (json.JSONDecodeError, IOError):
                    logs = []
            logs.append(log_entry)
            try:
                    DATA_DIR.mkdir(parents=True, exist_ok=True)
                # ... зчитування та оновлення логів ...
                    with open(LOG_FILE, "w", encoding="utf-8") as f:
                     json.dump(logs, f, indent=4, ensure_ascii=False)
            except (PermissionError, IOError) as e:
                    print(f"[Помилка запису лог-файлу JSON]: {e}")

    return wrapper

@log_event
def login(username: str, password: str) -> bool:
    try:
        if not username or not password:
            raise ValueError("Логін та пароль не можуть бути порожніми")

        salt = str(VARIANT_NUMBER).zfill(5)
        input_hash = generate_hash(password, salt=salt)
        users_db = load_users_db()

        for user in users_db:
            if (
                user["username"] == username
                and user["password_hash"] == input_hash
            ):
                return True
        return False

    except (ValueError, ValidationError) as e:
        print(f"[Помилка авторизації для {username}]: {e}")
        return False



def main():
    print(
        f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER} \n"
    )

    # Кортеж users_to_register з 10 записів 
    users_to_register = (
        ("lisa", "1лрлрлрлорло23!"),
        ("bob", "Password2023!2222222222"),
        ("nelli", "Shorjdhksjhdfkt1!"),  
        ("david", "048924972347fdwfsd0"),
        ("eve", "12344fdsfdsf56"),
        ("vika", "0987654321"),
        ("anna", "Passsdfword19373"),
        ("vova", "dsjgsdfsfdsfddjs"),
        ("ivan", "12j1hfdsffsdfjJHUb42974"),
        ("sofi", "Password11111111111"),
    )

    # Обробка винятків
    try:
        print("РЕЄСТРАЦІЯ КОРИСТУВАЧІВ ТА ЗБЕРЕЖЕННЯ У CSV ")
        create_users(users_to_register)

        print("\nБАЗА ДАНИХ ")
        users_db = load_users_db()
        print(f"{'Логін'} | {'Хеш пароля'}")
        for user in users_db:
            print(f"{user['username']} | {user['password_hash']}")

        print("\nАВТЕНТИФІКАЦІЯ ТА ЛОГУВАННЯ У JSON ")
        test_logins = [
            ("ivan", "12j1hfdsffsdfjJHUb42974"),
            ("bob", "Password2023!2222222222"),
            ("lisa", "1лрлрлрлорло23!"),
        ]

        print(f"{'Користувач'} | {'Пароль'} | {'Результат входу'}")
        for un, pw in test_logins:
            res = login(un, pw)
            status = "Успішно (True)" if res else "Відхилено (False)"
            print(f"{un} | {pw} | {status}")
    except Exception as e:
        print(f"[Помилка виконання у main]: {e}")

if __name__ == "__main__":
    main()