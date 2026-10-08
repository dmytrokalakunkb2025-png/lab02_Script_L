import argparse
import sys

# Імпорти адаптовані під те, що всі файли лежать в одній папці
from task1 import User, Admin, UserAccount
from task2 import analyze_emails

def run_demo():
    print("=== Демонстрація Завaдання 1 (Модель користувача) ===")
    admin = Admin("dimka_bog", "dmytro.kalakun.kb2025@lpnu.ua", permissions=["read", "write", "delete"])
    admin.set_password("SuperSecret1!")
    
    account = UserAccount(admin)
    print(f"Створено акаунт: {account['user']}")
    
    print("\nСпроба входу з неправильним паролем:")
    account.login("WrongPass", "192.168.1.10")
    
    print("\nСпроба входу з правильним паролем:")
    account.login("SuperSecret1!", "192.168.1.10")
    print(f"Аутентифіковано: {account.is_authenticated()}")
    
    print("\nВихід із системи:")
    account.logout()
    print(f"Аутентифіковано: {account.is_authenticated()}")
    
    print("\n=== Аудит подій ===")
    account["audit_log"].show_all()

def main():
    parser = argparse.ArgumentParser(description="Лабораторна робота №2 - Калакун")
    subparsers = parser.add_subparsers(dest="command", help="Команди: demo або analyze")

    # Команда demo (для Завдання 1)
    demo_parser = subparsers.add_parser("demo", help="Запуск демонстрації Завдання 1")

    # Команда analyze (для Завдання 2 - Варіант 12)
    analyze_parser = subparsers.add_parser("analyze", help="Аналіз поштових заголовків (Завдання 2)")
    analyze_parser.add_argument("--mail-log", required=True, help="Шлях до файлу логів (JSON)")
    analyze_parser.add_argument("--suspicious-keywords", help="Шлях до файлу зі словником стоп-слів")
    analyze_parser.add_argument("--out-csv", help="Шлях для збереження звіту")
    analyze_parser.add_argument("--debug", action="store_true", help="Увімкнути режим налагодження")

    args = parser.parse_args()

    if args.command == "demo":
        run_demo()
    elif args.command == "analyze":
        analyze_emails(args.mail_log, args.suspicious_keywords, args.out_csv, args.debug)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()