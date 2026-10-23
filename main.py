import sys
import io
import logging
import time
import os
import csv
import re
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from webdriver_manager.chrome import ChromeDriverManager
from gologin import GoLogin
import config

# --- КОНСТАНТЫ ---
TARGET_URL = "https://pixelscan.net/fingerprint-check"

# --- НАСТРОЙКА ЛОГИРОВАНИЯ ---
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
logging.getLogger('WDM').setLevel(logging.ERROR)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(config.LOG_FILE, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


# --- БИЗНЕС-ЛОГИКА ПАРСИНГА ---

def parse_pixelscan(driver):
    """Парсинг данных со страницы Pixelscan"""
    result_data = {
        "Browser": None, "Location": None, "Proxy": None,
        "Fingerprint": None, "Overall_Status": None
    }

    try:
        logger.info("Ожидание завершения сканирования...")

        # Ждем появления конкретного статуса
        WebDriverWait(driver, config.SCAN_WAIT_TIME).until(
            lambda d: any(word in d.find_element(By.CLASS_NAME, "status-text").text.lower()
                          for word in ["consistent", "inconsistent"])
        )

        logger.info("Сбор данных...")

        def is_data_ready(d):
            cards = d.find_elements(By.CLASS_NAME, "checker-card__info")
            return cards and all("Collecting" not in c.text for c in cards)

        WebDriverWait(driver, config.SCAN_WAIT_TIME).until(is_data_ready)
        time.sleep(1)

        status_text = driver.find_element(By.CLASS_NAME, "status-text").text
        result_data["Overall_Status"] = status_text.replace("Your Browser Fingerprint is", "").strip()

        for card in driver.find_elements(By.CLASS_NAME, "checker-card__info"):
            try:
                label = card.find_element(By.CLASS_NAME, "checker-card__label").text.strip()
                value = card.find_element(By.CSS_SELECTOR, "p[checkerValue]").text.strip()
                if label in result_data:
                    result_data[label] = value
            except NoSuchElementException:
                continue

        return result_data
    except TimeoutException:
        logger.error("Превышено время ожидания сканирования (статус не определился).")
        return None
    except Exception as e:
        logger.error(f"Ошибка при парсинге: {e}")
        return None


# --- ФОРМИРОВАНИЕ ОТЧЕТА ---

def generate_report(data, sdk_log=None):
    """Генерирует текстовый отчет на основе данных"""
    if not data:
        return "ОШИБКА: Данные не получены."

    report = [f"Профиль: {data.get('id', 'Unknown')}"]

    if sdk_log:
        ip_match = re.search(r"'lastIp': '([^']+)'", sdk_log)
        country_match = re.search(r"'country': '([^']+)'", sdk_log)
        city_match = re.search(r"'city': '([^']+)'", sdk_log)
        if ip_match:
            info = f"IP по данным GoLogin: {ip_match.group(1)}"
            if country_match and city_match:
                info += f" ({country_match.group(1)}, {city_match.group(1)})"
            report.append(info)

    b = str(data.get("Browser") or "")
    loc = str(data.get("Location") or "")
    prx = str(data.get("Proxy") or "")
    fp = str(data.get("Fingerprint") or "")
    status = str(data.get("Overall_Status") or "").lower()

    status_map = {
        "consistent": "CONSISTENT (Готов к работе)",
        "inconsistent": "INCONSISTENT (Требует исправления)"
    }
    report.append(f"Статус: {status_map.get(status, status.upper() or 'НЕТ ДАННЫХ')}")

    report.append(f"Браузер: {b if 'Collecting' not in b else 'Нет данных'}")
    report.append(f"IP Локация: {loc if 'Collecting' not in loc else 'Нет данных'}")
    report.append(f"Прокси: {prx if 'Collecting' not in prx else 'Нет данных'}")
    report.append(f"Отпечаток: {fp if 'Collecting' not in fp else 'Нет данных'}")

    warnings = []
    if "Linux" in b:
        warnings.append("ОС Linux (неестественно для US/EU).")
    if "no proxy" in prx.lower():
        warnings.append("Pixelscan не увидел прокси в карточке.")

    if warnings:
        report.append("Внимание: " + " ".join(warnings))

    return "\n".join(report)


# --- РАБОТА С БРАУЗЕРОМ (DRY) ---

def create_driver(debugger_address, chromium_version):
    """Централизованное создание WebDriver с оптимизацией"""
    chrome_options = webdriver.ChromeOptions()
    chrome_options.add_experimental_option("debuggerAddress", debugger_address)
    chrome_options.add_experimental_option("prefs", {"profile.managed_default_content_settings.images": 2})

    driver_path = ChromeDriverManager(driver_version=chromium_version).install()
    service = Service(executable_path=os.path.join(os.path.dirname(driver_path), "chromedriver.exe"))
    driver = webdriver.Chrome(service=service, options=chrome_options)
    driver.implicitly_wait(5)
    return driver


def check_single_profile(gl, profile_id):
    """Запуск и проверка одного профиля"""
    logger.info(f"--- Проверка профиля {profile_id} ---")

    sdk_output = ""
    old_stdout = sys.stdout

    try:
        gl.setProfileId(profile_id)
        sys.stdout = io.StringIO()
        debugger_address = gl.start()
        sdk_output = sys.stdout.getvalue().replace('profile stopped', '').strip()
        sys.stdout = old_stdout

        chromium_version = gl.get_chromium_version()

    except Exception as e:
        sys.stdout = old_stdout
        logger.error(f"Ошибка запуска профиля {profile_id}: {e}")
        return {"id": profile_id, "status": "launch_error", "error": str(e)}

    driver = None
    try:
        driver = create_driver(debugger_address, chromium_version)
        driver.get(TARGET_URL)
        data = parse_pixelscan(driver)

        if data:
            data["id"] = profile_id
            data["sdk_log"] = sdk_output
            return data
        return {"id": profile_id, "status": "parse_error", "sdk_log": sdk_output}
    except Exception as e:
        logger.error(f"Ошибка Selenium для профиля {profile_id}: {e}")
        return {"id": profile_id, "status": "selenium_error", "error": str(e), "sdk_log": sdk_output}
    finally:
        if driver:
            try:
                driver.quit()
            except:
                pass
        sys.stdout = io.StringIO()
        try:
            gl.stop()
        except:
            pass
        sys.stdout = old_stdout


# --- ТОЧКА ВХОДА ---

def main():
    logger.info("--- Запуск скрипта проверки Pixelscan ---")

    if not config.GL_API_TOKEN or config.GL_API_TOKEN == "ВАШ_ТОКЕН_ЗДЕСЬ":
        logger.error("Укажите реальный GL_API_TOKEN в config.py")
        return

    gl = GoLogin({"token": config.GL_API_TOKEN, "extra_params": ["--headless"]})

    logger.info("Загрузка списка профилей из GoLogin...")
    try:
        profiles_response = gl.profiles()
        profiles = profiles_response.get('profiles', []) if isinstance(profiles_response, dict) else profiles_response
    except Exception as e:
        logger.error(f"Ошибка получения списка профилей: {e}")
        return

    if not profiles:
        logger.warning("В вашем аккаунте нет профилей.")
        return

    print("\n" + "=" * 60 + "\n ДОСТУПНЫЕ ПРОФИЛИ:\n" + "=" * 60)
    for idx, p in enumerate(profiles, 1):
        name = p.get('name') or p.get('title') or f"Profile_{p.get('id')}"
        print(f"[{idx}] {name} (ID: {p.get('id')})")
    print("=" * 60 + "\n")

    user_input = input("Введите номера профилей (через запятую) или 'all': ").strip().lower()

    selected_profiles = []
    if user_input == 'all':
        selected_profiles = profiles
    else:
        try:
            indices = [int(i.strip()) - 1 for i in user_input.split(',')]
            selected_profiles = [profiles[i] for i in indices if 0 <= i < len(profiles)]
        except ValueError:
            logger.error("Неверный формат ввода.")
            return

    if not selected_profiles:
        logger.warning("Не выбрано ни одного профиля.")
        return

    logger.info(f"Начинаем проверку {len(selected_profiles)} профилей...")

    with open("mass_check_results.csv", mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ID", "Имя", "Статус", "Браузер", "Локация", "Прокси", "Отпечаток", "Ошибка"])

        for p in selected_profiles:
            pid = p.get('id')
            pname = p.get('name') or p.get('title') or "NoName"

            result = check_single_profile(gl, pid)

            print("\n" + "-" * 50)
            print(generate_report(result, result.get("sdk_log")))
            print("-" * 50)

            writer.writerow([
                pid, pname,
                result.get("Overall_Status") or result.get("status") or "",
                result.get("Browser") or "",
                result.get("Location") or "",
                result.get("Proxy") or "",
                result.get("Fingerprint") or "",
                result.get("error") or ""
            ])
            time.sleep(3)

    logger.info("--- Проверка завершена. Результаты в mass_check_results.csv ---")


if __name__ == "__main__":
    main()