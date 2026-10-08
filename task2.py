import argparse
import json
import csv
import logging
import re
from pathlib import Path

def setup_logger(debug=False):
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="[%(levelname)s] %(message)s"
    )
    return logging.getLogger(__name__)

def extract_domain(email_address: str) -> str:
    """Витягує домен з email-адреси за допомогою регулярних виразів."""
    try:
        if not email_address or not isinstance(email_address, str):
            return ""
        match = re.search(r"@([\w.-]+)", email_address)
        return match.group(1).lower() if match else ""
    except Exception:
        # Ловимо можливі помилки, якщо передано невідповідний тип даних
        return ""

def count_received_hops(received_data) -> int:
    """Обчислює кількість проміжних вузлів у заголовках Received."""
    try:
        if isinstance(received_data, list):
            return len(received_data)
        elif isinstance(received_data, str):
            return len(received_data.split("Received:")) - 1
        return 0
    except Exception:
        return 0

def analyze_emails(mail_log_path: str, keywords_path: str, output_csv: str, debug: bool):
    logger = setup_logger(debug)
    
    mail_file = Path(mail_log_path)
    if not mail_file.exists():
        logger.error(f"Файл {mail_log_path} не знайдено.")
        return

    # Завантаження стоп-слів
    stopwords = []
    if keywords_path:
        kw_file = Path(keywords_path)
        if kw_file.exists():
            try:
                with open(kw_file, 'r', encoding='utf-8') as f:
                    stopwords = [line.strip().lower() for line in f if line.strip()]
            except IOError as e:
                logger.error(f"Помилка доступу до файлу стоп-слів {keywords_path}: {e}")
            except Exception as e:
                logger.error(f"Неочікувана помилка читання словника: {e}")
        else:
            logger.warning(f"Словник {keywords_path} не знайдено, перевірка теми пропущена.")

    logger.info(f"Analyzing email headers dump from {mail_log_path}...")
    
    # Читання JSON
    try:
        with open(mail_file, 'r', encoding='utf-8') as f:
            emails = json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"Файл JSON пошкоджено або він має невірний формат: {e}")
        return
    except Exception as e:
        logger.error(f"Помилка відкриття JSON файлу: {e}")
        return

    # Перевірка чи дані є списком
    if not isinstance(emails, list):
        logger.error("Структура JSON має бути списком об'єктів. Перевірте файл.")
        return

    logger.info(f"Total emails inspected: {len(emails)}.\n")
    print("=== Phishing & Spoofing Audit Results ===")

    results = []

    # Обробка кожного листа
    for idx, email in enumerate(emails, start=1):
        try:
            # Якщо замість словника попався інший тип даних - пропускаємо
            if not isinstance(email, dict):
                logger.warning(f"Пропущено Email ID #{idx}: неправильний формат даних (очікувався словник).")
                continue

            sender_from = email.get("From", "")
            return_path = email.get("Return-Path", "")
            reply_to = email.get("Reply-To", "")
            subject = email.get("Subject", "")
            received = email.get("Received", [])

            domain_from = extract_domain(sender_from)
            domain_return = extract_domain(return_path)
            domain_reply = extract_domain(reply_to)

            mismatches = []
            if domain_return and domain_from != domain_return:
                mismatches.append(f"From: '{sender_from}' vs Return-Path: '{return_path}'")
            if domain_reply and domain_from != domain_reply:
                mismatches.append(f"Reply-To Mismatch: '{reply_to}'")

            # Перевірка теми на стоп-слова
            found_stopwords = []
            try:
                if isinstance(subject, str):
                    found_stopwords = [word for word in stopwords if word in subject.lower()]
            except Exception as e:
                logger.debug(f"Помилка при перевірці теми для Email ID #{idx}: {e}")
            
            hop_count = count_received_hops(received)
            
            risk_score = 0
            if mismatches:
                risk_score += 50
            if found_stopwords:
                risk_score += 30
            if hop_count > 5:  # Більше 5 вузлів вважаємо аномалією
                risk_score += 20

            risk_level = "HIGH RISK" if risk_score >= 70 else "WARNING" if risk_score >= 40 else "SAFE"

            if risk_score >= 40:
                print(f"[{risk_level}] Email ID #{idx} |")
                if mismatches:
                    print(f"  Sender Mismatch: {', '.join(mismatches)}")
                print(f"  Subject: \"{subject}\"")
                if found_stopwords:
                    print(f"  Stopwords Found: {found_stopwords}")
                print(f"  Hop Count: {hop_count} intermediate relays")
                print(f"  Risk Score: {risk_score}/100\n")

            results.append({
                "Email_ID": idx,
                "From": sender_from,
                "Subject": subject,
                "Hop_Count": hop_count,
                "Risk_Score": risk_score,
                "Status": risk_level
            })

        except Exception as e:
            # Якщо виникає непередбачувана помилка з конкретним листом, ловимо її тут,
            # щоб програма не зупинялась і могла обробити наступні листи.
            logger.error(f"Сталася критична помилка під час аналізу Email ID #{idx}: {e}")
            continue

    # Запис у CSV
    if output_csv:
        try:
            with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=["Email_ID", "From", "Subject", "Hop_Count", "Risk_Score", "Status"])
                writer.writeheader()
                writer.writerows(results)
            logger.info(f"Phishing audit summary exported to {output_csv}")
        except PermissionError:
            logger.error(f"Помилка: немає прав на запис у файл {output_csv}. Можливо, він зараз відкритий у Excel?")
        except Exception as e:
            logger.error(f"Неочікувана помилка запису CSV: {e}")
