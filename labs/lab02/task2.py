import argparse # Дозволяє передавати параметри у програму під час запуску
import csv
import json
import logging
import re # Модуль регулярних виразів для перевірки формату
from dataclasses import asdict, dataclass
from pathlib import Path

IP_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)
MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")


@dataclass
class ARPEntry: # Об'єкт для збереження інформації про один перевірений запис
    ip: str
    mac: str
    interface: str
    type: str


@dataclass
class ARPAuditReport: # Загальна структура підсумкового звіту
    total_parsed: int
    valid_entries: int
    invalid_syntax_count: int
    spoofing_conflicts: list[dict]


def parse_arp_csv(file_path: Path) -> list[dict]:
    entries = []
    try:
        with open(file_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                clean_row = {k.strip(): v.strip() for k, v in row.items() if k and v}
                entries.append(clean_row)
    except FileNotFoundError:
        logging.error(f"Файл не знайдено за шляхом: {file_path}")
        raise
    except PermissionError:
        logging.error(f"Недостатньо прав для читання файлу: {file_path}")
        raise
    except csv.Error as e:
        logging.error(f"Помилка зчитування CSV файлу {file_path}: {e}")
        raise
    except Exception as e:
        logging.error(f"Невідома помилка при відкритті CSV {file_path}: {e}")
        raise

    return entries


def analyze_arp_data(data: list[dict]):
    valid_entries: list[ARPEntry] = []
    invalid_count = 0
    mac_to_ips: dict[str, set[str]] = {}

    for row in data:
        ip = row.get("IP Address", "")
        mac = row.get("MAC Address", "")
        iface = row.get("Interface", "")
        e_type = row.get("Type", "")

        if not IP_REGEX.match(ip) or not MAC_REGEX.match(mac):
            invalid_count += 1
            logging.warning(f"Невалідний запис: IP={ip}, MAC={mac}")
            continue
        # нормалізація MAC-адреси для уніфікації (великі літери та двокрапки)
        mac_norm = mac.upper().replace("-", ":")
        entry = ARPEntry(ip=ip, mac=mac_norm, interface=iface, type=e_type)
        valid_entries.append(entry)
        # Групування IP-адрес за MAC-адресою
        if mac_norm not in mac_to_ips:
            mac_to_ips[mac_norm] = set()
        mac_to_ips[mac_norm].add(ip)

    conflicts = []
    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            conflicts.append({"mac": mac, "associated_ips": list(ips)})

    return valid_entries, invalid_count, conflicts


def main():
    parser = argparse.ArgumentParser(description="Аудитор ARP-таблиць")
    
    parser.add_argument(
        "--arp-file", 
        type=Path, 
        default=Path("labs/lab02/data/data_v11/arp_table.csv"), 
        help="Шлях до CSV файлу ARP"
    )
    parser.add_argument(
        "--output-json", 
        type=Path, 
        default=Path("labs/lab02/data/data_v11/arp_security_alerts.json"), 
        help="Шлях для збереження звіту"
    )
    parser.add_argument(
        "--detect-spoofing", 
        action="store_true", 
        default=True,  # Увімкнено за замовчуванням
        help="Перевірка ARP-Spoofing"
    )
    parser.add_argument("--log-file", type=Path, help="Файл логування")
    args = parser.parse_args()

    handlers = [logging.StreamHandler()]
    if args.log_file:
        handlers.append(logging.FileHandler(args.log_file, encoding="utf-8"))

    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s", handlers=handlers)

    if not args.arp_file.exists():
        logging.error(f"Файл не знайдено: {args.arp_file}")
        return
    try:
        raw_data = parse_arp_csv(args.arp_file)
    except Exception:
        logging.error("Аналіз перервано через помилку зчитування файлу.")
        return

    valid_entries, invalid_count, conflicts = analyze_arp_data(raw_data)

    print("\nValidated Entries Summary")
    print(f"Valid IP/MAC Pairs : {len(valid_entries)}")
    print(f"Invalid Syntax     : {invalid_count}")

    if args.detect_spoofing and conflicts:
        print("\n=CRITICAL SECURITY ALERTS: ARP-SPOOFING DETECTED")
        for c in conflicts:
            print(f"[ALERT] MAC {c['mac']} пов'язана з кількома IP: {', '.join(c['associated_ips'])}")

    report = ARPAuditReport(
        total_parsed=len(raw_data),
        valid_entries=len(valid_entries),
        invalid_syntax_count=invalid_count,
        spoofing_conflicts=conflicts,
    )

    try:
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(asdict(report), f, indent=4, ensure_ascii=False)
        logging.info(f"Звіт успішно збережено у {args.output_json}")
    except PermissionError:
        logging.error(f"Недостатньо прав для запису підсумкового JSON у: {args.output_json}")
    except OSError as e:
        logging.error(f"Помилка введення/виведення під час запису звіту: {e}")


if __name__ == "__main__":
    main()
# python -m labs.lab02.main analyze --arp-file labs/lab02/data/data_v11/arp_table.csv --output-json labs/lab02/data/arp_security_alerts.json --detect-spoofing