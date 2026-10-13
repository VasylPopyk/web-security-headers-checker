# Web Security Headers Checker

Python-інструмент для аудиту HTTP-заголовків безпеки веб-сайтів. Надсилає GET-запит до вказаних доменів, перевіряє наявність критичних заголовків, формує оцінку захищеності у відсотках і для кожного відсутнього заголовка пояснює, чому він важливий і як його додати.

![Python](https://img.shields.io/badge/python-3.8+-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Можливості

- Перевірка шести заголовків безпеки з вагами
- Для кожного відсутнього заголовка: пояснення ризику та готовий приклад виправлення
- Сканування одного домену або списку з файлу
- Оцінка захищеності у балах і відсотках для кожного домену
- Звітність у терміналі та експорт у JSON або CSV
- Обробка помилок мережі та таймаутів

## Встановлення

```bash
pip install requests
```

Потрібен Python 3.8 або новіший.

## Використання

Перевірка одного домену:

```bash
python security_checker.py -d example.com
```

Сканування списку доменів і збереження звіту у JSON:

```bash
python security_checker.py -f domains.txt -o security_report --format json
```

Експорт у CSV:

```bash
python security_checker.py -f domains.txt -o security_report --format csv
```

Формат файлу `domains.txt` (рядки, що починаються з `#`, ігноруються):

```text
example.com
# коментар
github.com
```

## Система оцінювання

| Заголовок | Вага | Що захищає |
|---|---|---|
| Strict-Transport-Security | 25 | Примусовий HTTPS, захист від MitM |
| Content-Security-Policy | 25 | Захист від XSS |
| X-Frame-Options | 20 | Захист від clickjacking |
| X-Content-Type-Options | 15 | Заборона MIME-sniffing |
| Referrer-Policy | 10 | Контроль передачі URL при переходах |
| Permissions-Policy | 5 | Обмеження доступу до камери, мікрофона, геолокації |

Загальний максимум — 100 балів. Рівні оцінки: від 80% — високий рівень, від 50% — середній, нижче 50% — критично низький.

Скрипт перевіряє лише наявність заголовка, а не коректність його значення. Наприклад, `Content-Security-Policy: default-src *` буде зарахований як присутній.

## Обмеження

- Перевіряється лише наявність заголовків, без аналізу їхніх значень.
- Redirect-ланцюжки відстежуються через `allow_redirects=True`, тому фінальна відповідь може бути з іншого домену.
- Скрипт не є повноцінним сканером безпеки і не замінює професійні інструменти.

## Приклад виводу

```text
======================================================================
 TARGET DOMAIN: example.com (Final URL: https://example.com/)
======================================================================
 Security Score: 60/100 points (60.0%)
 Status: MEDIUM LEVEL (NEEDS IMPROVEMENT)
----------------------------------------------------------------------
 [✓] Strict-Transport-Security: PRESENT
 [❌] Content-Security-Policy: MISSING (-25 pts)
     💡 Why it matters: Protects against Cross-Site Scripting (XSS) attacks by restricting script sources.
     🛠️ How to fix:     Add header: Content-Security-Policy: default-src 'self'
----------------------------------------
======================================================================
```

## Ліцензія

MIT

---

# Web Security Headers Checker

A Python tool for auditing HTTP security headers on websites. It sends a GET request to the specified domains, checks for critical security headers, produces a security score as a percentage, and explains for each missing header why it matters and how to add it.

![Python](https://img.shields.io/badge/python-3.8+-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Features

- Checks six security headers with weights
- For each missing header: explanation of the risk and a ready-to-use fix
- Scans a single domain or a list from a file
- Score and percentage per domain
- Terminal report and export to JSON or CSV
- Handles network errors and timeouts

## Installation

```bash
pip install requests
```

Requires Python 3.8 or newer.

## Usage

Check a single domain:

```bash
python security_checker.py -d example.com
```

Scan a list of domains and save a JSON report:

```bash
python security_checker.py -f domains.txt -o security_report --format json
```

Export to CSV:

```bash
python security_checker.py -f domains.txt -o security_report --format csv
```

Format of `domains.txt` (lines starting with `#` are ignored):

```text
example.com
# comment
github.com
```

## Scoring

| Header | Weight | What it protects against |
|---|---|---|
| Strict-Transport-Security | 25 | Forced HTTPS, MitM attacks |
| Content-Security-Policy | 25 | XSS |
| X-Frame-Options | 20 | Clickjacking |
| X-Content-Type-Options | 15 | MIME sniffing |
| Referrer-Policy | 10 | Leaking URLs on navigation |
| Permissions-Policy | 5 | Unrestricted access to camera, microphone, geolocation |

Maximum total is 100 points. Rating levels: 80% and above is high, 50% and above is medium, below 50% is critically low.

The script only checks whether a header is present, not whether its value is correct. For example, `Content-Security-Policy: default-src *` counts as present.

## Limitations

- Only header presence is checked, not header values.
- Redirects are followed via `allow_redirects=True`, so the final response may come from a different domain.
- This is not a full security scanner and does not replace professional tools.

## Example Output

```text
======================================================================
 TARGET DOMAIN: example.com (Final URL: https://example.com/)
======================================================================
 Security Score: 60/100 points (60.0%)
 Status: MEDIUM LEVEL (NEEDS IMPROVEMENT)
----------------------------------------------------------------------
 [✓] Strict-Transport-Security: PRESENT
 [❌] Content-Security-Policy: MISSING (-25 pts)
     💡 Why it matters: Protects against Cross-Site Scripting (XSS) attacks by restricting script sources.
     🛠️ How to fix:     Add header: Content-Security-Policy: default-src 'self'
----------------------------------------
======================================================================
```

## License

MIT