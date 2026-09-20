import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),'../../')))
from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER


from labs.lab01.task1 import main as task1_main
from labs.lab01.task2 import main as task2_main
from labs.lab01.task3 import main as task3_main


def main():

    print(
        f"  ЛАБОРАТОРНА РОБОТА №1 | {STUDENT_NAME} | {GROUP_NAME} | Варіант №{VARIANT_NUMBER}"
    )


    print("\nЗАВДАННЯ 1: Аналіз та валідація паролів ")
    task1_main()


    print("ЗАВДАННЯ 2: Контроль доступу (MAC) ")
    task2_main()


    print("ЗАВДАННЯ 3: Реєстрація, CSV, JSON та Автентифікація ")
    task3_main()

    print(" Всі завдання Лабораторної роботи №1 виконано")
    print("=" * 65)


if __name__ == "__main__":
    main()