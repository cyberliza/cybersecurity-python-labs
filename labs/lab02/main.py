import sys
from labs.lab02.task1 import Admin, AuditLog, User, UserAccount


def run_demo():
    print("Завдання 1 (ООП та Безпека)")
    audit_log = AuditLog()  # Журнал аудиту

    # Створення користувачів та адміна
    user = User(username="l_iza", email="liza@gmail.com")
    user.set_password("3264646192374hrfjre!")

    admin = Admin(username="alex", email="alex.sasha@gmail.com")
    admin.set_password("dfkhdk")
    admin.grant_permission("READ_LOGS")
    admin.grant_permission("MANAGE_USERS")

    print(f"Створено: {user}")
    print(f"Створено: {admin}")

    # Обліковий запис та вхід
    account = UserAccount(user=user, audit_log=audit_log)

    print("\n Тест 1: Невірний пароль")
    success = account.login("l_iza", "123", ip="192.168.1.50")
    print(f"Результат входу: {success} | Статус автентифікації: {account.is_authenticated()}")

    print("\nТест 2: Успішний вхід")
    success = account.login("l_iza", "3264646192374hrfjre!", ip="192.168.1.50")
    print(f"Результат входу: {success} | Статус автентифікації: {account.is_authenticated()}")

    # 3. Доступ через __getitem__ та __setitem__
    print("\nТест 3: Спеціальні методи __getitem__ / __setitem__ ---")
    print(f"Отримання email через account: {account['email']}")
    account["email"] = "liza2@gmail.com"
    print(f"Оновлений email через account: {account['email']}")

    try:
        account["email"] = "Неправильний формат"
    except ValueError as e:
        print(f"Очікувана помилка валідації: {e}")

    # Перевірка адмінправ
    print("\nТест 4: Перевірка прав Admin")
    print(f"Адмін має 'READ_LOGS'?: {admin.has_permission('READ_LOGS')}")
    admin.revoke_permission("READ_LOGS")
    print(f"Після вилучення 'READ_LOGS'?: {admin.has_permission('READ_LOGS')}")

    # Вихід із системи
    print("\nТест 5: Вихід")
    account.logout()
    print(f"Статус автентифікації після logout: {account.is_authenticated()}")

    # Журнал аудиту
    audit_log.show_all()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        run_demo()
    elif len(sys.argv) > 1 and sys.argv[1] == "analyze":
        from labs.lab02.task2 import main as task2_main
        sys.argv.pop(1)  # Видаляємо 'analyze'

        # Якщо після 'analyze' нічого не вказали до аргументів додамо стандартні значення
        if len(sys.argv) == 1:
            sys.argv.extend([
                "--arp-file", "labs/lab02/data/data_v11/arp_table.csv",
                "--output-json", "labs/lab02/data/data_v11/arp_security_alerts.json",
                "--detect-spoofing"
            ])
            
        task2_main()
    else:
        print("Запуск:")
        print("  python -m labs.lab02.main demo")
        print("  python -m labs.lab02.main analyze")

if __name__ == "__main__":
    main()