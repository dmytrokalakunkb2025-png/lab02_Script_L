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
    if not email_address:
        return ""
    match = re.search(r"@([\w.-]+)", email_address)
    return match.group(1).lower() if match else ""

def count_received_hops(received_data) -> int:
    """Обчислює кількість проміжних вузлів у заголовках Received."""
    if isinstance(received_data, list):
        return len(received_data)
    elif isinstance(received_data, str):
        return len(received_data.split("Received:")) - 1
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
            with open(kw_file, 'r', encoding='utf-8') as f:
                stopwords = [line.strip().lower() for line in f if line.strip()]
        else:
            logger.warning(f"Словник {keywords_path} не знайдено, перевірка теми пропущена.")

    logger.info(f"Analyzing email headers dump from {mail_log_path}...")
    
    try:
        with open(mail_file, 'r', encoding='utf-8') as f:
            emails = json.load(f)
    except Exception as e:
        logger.error(f"Помилка читання JSON: {e}")
        return

    logger.info(f"Total emails inspected: {len(emails)}.\n")
    print("=== Phishing & Spoofing Audit Results ===")

    results = []

    for idx, email in enumerate(emails, start=1):
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

        found_stopwords = [word for word in stopwords if word in subject.lower()]
        
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

    # Запис у CSV
    if output_csv:
        try:
            with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=["Email_ID", "From", "Subject", "Hop_Count", "Risk_Score", "Status"])
                writer.writeheader()
                writer.writerows(results)
            logger.info(f"Phishing audit summary exported to {output_csv}")
        except Exception as e:
            logger.error(f"Помилка запису CSV: {e}")