import sys
import os
import random


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),'../../')))
from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER

passwords = ["APT@Detect10n", "simple", "Red@Team2023", "participant",
"Blue@T3am", "common123", "Purple@T34m", "regular123", "Gr33n@Team",
"normal123"]
criteria = {"min_length": 7, "require_digits": True, "require_upper": True,
"require_special": True}
forbidden_passwords = {"simple", "participant", "common123", "regular123",
"normal123", "test"}

def analyze_password(
    passwords: str, all_passwords: list, criteria: dict, forbidden_passwords: set
) -> str:
    min_len = criteria["min_length"]
    has_digit = any(c.isdigit() for c in passwords)
    has_upper = any(c.isupper() for c in passwords)
    has_lower = any(c.islower() for c in passwords)
    has_special = any(not c.isalnum() for c in passwords)

    if passwords in forbidden_passwords or len(passwords) < min_len:
        return "Заборонений"

    all_checks = [has_digit, has_upper, has_special, has_lower]

    if all(all_checks):
        if len(passwords) >= min_len + 4 and all_passwords.count(passwords) == 1:
            return "Дуже сильний"
        return "Сильний"

    if any(all_checks):
        return "Слабкий" if sum(all_checks) == 1 else "Середній"

    return "Слабкий"


def main():
    print(
        f" Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER} "
    )

    list = passwords.copy()  # Копіюємо список паролів
    random.seed(VARIANT_NUMBER) # Встановлюємо насіння генератора випадкових чисел
    dup = random.sample(range(len(list)), 3) #
    for idx in dup: 
        list.append(list[idx]) # 

    print(f"{'Пароль'} | {'Оцінка'}")
    for pwd in list:
        status = analyze_password(
            pwd, list, criteria, forbidden_passwords
        )
        print(f"{pwd} | {status}")


if __name__ == "__main__":
    main()