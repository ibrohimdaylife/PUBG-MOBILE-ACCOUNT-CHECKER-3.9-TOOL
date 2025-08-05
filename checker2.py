#developer : @ibrohim_Daylife
#if you fix problem, please let me know



from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import sys
import requests
import time
import uuid
import hashlib
import string
import random
import base64
from Crypto.Cipher import AES
import json
from Crypto.Util.Padding import unpad
from Crypto.Util.Padding import pad
from requests.auth import HTTPProxyAuth


email = input("✉️  Email kiriting: ").strip()
password_plain = input("🔑 Parol kiriting: ").strip()

randstr_input = input("🌀 randstr ni kiriting (masalan: @lu86i4s5bhj): ").strip()
ticket_input = input("🎫 ticket ni kiriting (masalan: terror_1001_2033864629_1753759516): ").strip()

#email = f"asdfgh{random.randint(100,9999)}@gmail.com";
#password_plain = "asdsadfgh77"

devices = {
    "SM-N975F": ("1440*3040", "9", "PI"),
    "SM-G998B": ("1440*3200", "11", "RP1A"),
    "SM-A715F": ("1080*2400", "10", "QP1A"),
    "SM-M526B": ("1080*2408", "11", "RP1A"),
    "SM-G991B": ("1080*2400", "12", "SP1A"),
    "SM-G973F": ("1440*3040", "9", "PQ3A"),
    "SM-A515F": ("1080*2400", "10", "QP1A")
}

architectures = ["arm64-v8a", "arm64-v8a+x86_64", "armeabi-v7a"]

android_builds = {
    "9": "API-28(samsung-user 9 PQ3A.190801.002 1234567 release-keys)",
    "10": "API-29(samsung-user 10 QP1A.190711.020 7654321 release-keys)",
    "11": "API-30(samsung-user 11 RP1A.200720.012 1928374 release-keys)",
    "12": "API-31(samsung-user 12 SP1A.210812.016 2837465 release-keys)",
    "13": "API-33(samsung-user 13 TP1A.220624.014 8374652 release-keys)"
}

# 🎲 Tasodifiy qurilma ma’lumotlari
model = random.choice(list(devices.keys()))
screen, android_version, build_id = devices[model]
arch = random.choice(architectures)
android_info = f"Android \\/ {android_builds[android_version]}"  # escape qilish shart

# 📱 User-Agent header — qurilmaga mos
#user_agent = f"Dalvik/2.1.0 (Linux; U; Android {android_version}; {model} Build/{build_id})"
user_agent = f"Dalvik/2.1.0 (Linux; U; Android 9; SM-N975F Build/PI)"

def solve_captcha(timeout=30):
    html_file = "file:///C:/Users/IBROHIM_RAQPT/Desktop/tset/iMSDKWebVerify.html"

    options = Options()
    driver = webdriver.Chrome(options=options)
    driver.get(html_file)

    print("CAPTCHA natijasini kutyapmiz...")

    start = time.time()
    result = None
    while time.time() - start < timeout:
        result = driver.execute_script("return window._captchaResult || null;")
        if result:
            break
        time.sleep(0.5)

    driver.quit()

    if result and result.get("randstr") and result.get("ticket"):
        return result.get("randstr"), result.get("ticket")
    else:
        print("❌ CAPTCHA yechilmadi yoki natija topilmadi.")
        sys.exit(1)
        
#randstr_input, ticket_input = [x.strip() for x in solve_captcha()]
#print(randstr_input, ticket_input)

def generate_fake_captcha_error(app_id='2033864629'):
    timestamp = int(time.time())
    randstr = '@' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    ticket = f'terror_1001_{app_id}_{timestamp}'
    
    return randstr, ticket

#fake_captcha = generate_fake_captcha_error()
#randstr_input = fake_captcha[0]
#ticket_input = fake_captcha[1]
#print(randstr_input, ticket_input)

def generate_iv():
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    random.seed(int(time.time()))
    iv = ''.join(random.choice(charset) for _ in range(16))
    return iv

def get_nanoseconds():
    return int(time.time() * 10000000000)

current_ms_nano = get_nanoseconds()
current_ms = int(str(current_ms_nano)[:13]) + random.randint(126, 363)
current_ts = str(current_ms_nano)[:10]
n_value = str(current_ms_nano)[-10:]

def generate_device_id():
    return str(uuid.uuid4())

device_id = generate_device_id()
#print(device_id)

def generate_md5_hashed_code(device_id, current_ms):
    suffix = "mqF74IPfly2hREYG"
    full_string = f"{device_id}{current_ms}{suffix}"
    md5_hash = hashlib.md5(full_string.encode()).hexdigest()
    return full_string, md5_hash

def md5_hash_password(text):
    return hashlib.md5(text.encode()).hexdigest()

def bytes_to_base64url(b):
    base64_str = base64.b64encode(b).decode('utf-8')
    return base64_str.replace('+', '-').replace('/', '_').rstrip('=')

def generate_uuid():
    return str(uuid.uuid4()).replace('-', '')

sGuestId_generator = generate_uuid()
#print(sGuestId_generator)

def generate_ugid(sguest_id):
    return hashlib.sha256(sguest_id.encode()).hexdigest()

sUgId_generator = generate_ugid(sGuestId_generator)
#print(sUgId_generator)


def generate_sid():
    uuid_str = str(uuid.uuid4())
    md5_hash = hashlib.md5(uuid_str.encode()).hexdigest()
    md5_substr = md5_hash[16:]  # oxirgi 16ta belgi
    return int(md5_substr, 16)

sid_generator = generate_sid()
#print(sid_generator)

with open("request_count.txt", "r") as file:
    request_count = int(file.read())

def build_login_request(current_ms_nano, current_ms, current_ts, n_value, randstr_input, ticket_input, email, password_plain):
    password_hashed = md5_hash_password(password_plain)
    
    current_ms_2 = int(current_ms) + 1  # dinfo uchun boshqa timestamp

    full_string, md5_value = generate_md5_hashed_code(device_id, current_ms_nano)

    # Eslatma: Android \/ API-28 bu joyda to'g'ri escape qilingan!
    #dinfo = f"1|43405|{model}|en|3.9.0|{current_ms_2}|2.25|{screen}|samsung|{sGuestId_generator}|{arch}|{android_info}"
    dinfo = f"1|43405|SM-N975F|en|3.9.0|{current_ms_2}|2.25|1920*1080|samsung|23892eabf941a0b0728901325f0a9c4f|arm64-v8a+x86_64|Android \\/ API-28(samsung-user 9.0.0 20171130.276299 release-keys)"

    request = (
        f"/account/login?account_plat_type=3&appid=dd921eb18d0c94b41ddc1a6313889627"
        f"&lang_type=en_US&os=1&s=1&seq=1320-{device_id}-{current_ms}-{request_count}&v=1"
        f"{{\"account\":\"{email}\",\"account_type\":1,\"area_code\":\"\",\"password\":\"{password_hashed}\","
        f"\"qcaptcha\":{{\"ret\":0,\"msg\":\"success\",\"randstr\":\"{randstr_input}\",\"ticket\":\"{ticket_input}\"}},"
        f"\"sid\":{sid_generator},\"pticket\":\"\",\"did\":\"{device_id}\","
        f"\"dinfo\":\"{dinfo}\","
        f"\"sGuestId\":\"{sGuestId_generator}\",\"sOriginalId\":\"{sGuestId_generator}\","
        f"\"iGameId\":\"1320\",\"iPlatform\":\"2\",\"sdkversion\":\"2.10.8\",\"gameversion\":\"3.9.0\","
        f"\"package_name\":\"com.tencent.ig\",\"extra_json\":\"{{\\\"actionType\\\":\\\"login\\\"}}\","
        f"\"sUgId\":\"62b6161a8d6b88264cc59863e39b4162320bfdb5adfeb9396fc3dff0a8f6d684\","
        f"\"ts\":{current_ts},\"n\":\"{n_value}\"}}{md5_value}"
    )

    #print("📦 Yakuniy so'rov:")
    #print(request)
    md5_hash_build = hashlib.md5(request.encode()).hexdigest()
    #print(md5_hash_build)
    #print("\n🔒 Yakuniy MD5(full_string):", md5_value)
    return email, password_hashed, dinfo, current_ts, n_value, md5_hash_build

# 🔄 Ishga tushurish
email, password_hashed, dinfo, current_ts, n_value, md5_hash_build = build_login_request(current_ms_nano, current_ms, current_ts, n_value, randstr_input, ticket_input, email, password_plain)

def build_encryption_plaintext(email, password_hashed, dinfo, ts, n, md5_hash_build, randstr_input, ticket_input):
    return (
        f'{{"account":"{email}","account_type":1,"area_code":"","password":"{password_hashed}",'
        f'"qcaptcha":{{"ret":0,"msg":"success","randstr":"{randstr_input}","ticket":"{ticket_input}"}},'
        f'"sid":{sid_generator},"pticket":"","did":"{device_id}",'
        f'"dinfo":"{dinfo}","sGuestId":"{sGuestId_generator}","sOriginalId":"{sGuestId_generator}",'
        f'"iGameId":"1320","iPlatform":"2","sdkversion":"2.10.8","gameversion":"3.9.0",'
        f'"package_name":"com.tencent.ig","extra_json":"{{\\"actionType\\":\\"login\\"}}",'
        f'"sUgId":"62b6161a8d6b88264cc59863e39b4162320bfdb5adfeb9396fc3dff0a8f6d684",'
        f'"ts":{ts},"n":"{n}"}}|{md5_hash_build}'
    )


#iv_input = input("IV ni kiriting (16 ta belgili matn):\n").strip()
#iv_input = "lZl5DEBCGT79RG71"
iv_input = generate_iv()
key_input = "bJMRPShoOYG207pm82iWPzOTyymqpFL7"
plaintext = build_encryption_plaintext(email, password_hashed, dinfo, current_ts, n_value, md5_hash_build, randstr_input, ticket_input)

def encrypt_aes_base64url(plaintext: str, key_input: str, iv_input: str) -> str:
    """
    AES-256-CBC orqali matnni shifrlaydi va Base64URL formatida qaytaradi.
    """
    try:
        # IV → UTF-8 baytlarga
        iv_bytes = iv_input.encode("utf-8")
        if len(iv_bytes) != 16:
            raise ValueError("IV uzunligi 16 bayt (16 ta belgili matn) bo‘lishi kerak.")

        # Kalit → UTF-8 baytlarga
        key_bytes = key_input.encode("utf-8")
        if len(key_bytes) != 32:
            raise ValueError("Kalit uzunligi noto'g'ri. 32 ta belgidan iborat bo‘lishi kerak (256 bit).")

        # Matnni UTF-8 kodlash + PKCS7 pad
        padded_plaintext = pad(plaintext.encode("utf-8"), AES.block_size)

        # AES/CBC shifrlash
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        ciphertext = cipher.encrypt(padded_plaintext)

        # IV + ciphertext → Base64URL
        full_data = iv_bytes + ciphertext
        encoded_result = bytes_to_base64url(full_data)

        return encoded_result

    except Exception as e:
        print("\n❌ Xatolik yuz berdi:", e)
        return None

natija = encrypt_aes_base64url(plaintext, key_input, iv_input)

def build_signed_login_url(current_ms: int, natija: str) -> str:
    json_body = {
        "e": natija
    }
    #print(json_body)

    extra = "3ec8cd69d71b7922e2a17445840866b26d86e283"
    path_and_query = (
        f"/account/login?account_plat_type=3&appid=dd921eb18d0c94b41ddc1a6313889627"
        f"&lang_type=en_US&os=1&s=1&seq=1320-{device_id}-{current_ms}-{request_count}&v=1"
    )

    full_string_sign = path_and_query + json.dumps(json_body, separators=(",", ":")) + extra
    md5_hash_sign = hashlib.md5(full_string_sign.encode()).hexdigest()

    return f"https://igame.msdkpass.com{path_and_query}&sig={md5_hash_sign}"

url = build_signed_login_url(current_ms, natija)
#print(url)

def decrypt_data(encrypted_data: str, key: str) -> str:
    # Base64URL decode (ba'zi "-" va "_" belgilarni "+" va "/" ga almashtiramiz)
    encrypted_data = encrypted_data.replace('-', '+').replace('_', '/')
    # Base64 decode
    encrypted_data_bytes = base64.b64decode(encrypted_data)

    # Kalit va IV
    key_bytes = key.encode('utf-8')
    iv = encrypted_data_bytes[:16]
    ciphertext = encrypted_data_bytes[16:]

    # AES decrypt
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)

    # Paddingni olib tashlash va UTF-8 ga o‘tkazish
    decrypted_text = unpad(decrypted, AES.block_size).decode('utf-8')

    return decrypted_text

def send_login_request(url: str, natija: str, user_agent):
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-N975F Build/PI)",
        "Host": "igame.msdkpass.com",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip"
    }

    # JSON stringni qo‘lda to‘g‘ri tayyorlab, serverga yuboramiz
    raw_json = json.dumps({"e": natija}, separators=(",", ":"))

    try:
        response = requests.post(url, headers=headers, data=raw_json)
        response.raise_for_status()
        return response.json()
    except requests.HTTPError as http_err:
        print(f"❌ HTTP xatolik: {http_err} | Status code: {response.status_code}")
        print("Javob:\n", response.text)
    except requests.RequestException as e:
        print("❌ Tarmoq xatoligi:", e)
    finally:
        # Har doim ishlaydigan qism: +1 qo‘shish
        with open("request_count.txt", "r") as file:
            count = int(file.read())
        count += 1
        with open("request_count.txt", "w") as file:
            file.write(str(count))


proxies_list = [
    "ip:port:user:pass"
]

def send_login_request2(url: str, natija: str, user_agent):
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": user_agent,
        "Host": "igame.msdkpass.com",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip"
    }

    raw_json = json.dumps({"e": natija}, separators=(",", ":"))

    # Tasodifiy proksi tanlash
    proxy_entry = random.choice(proxies_list)
    proxy_ip, proxy_port, proxy_user, proxy_pass = proxy_entry.split(":")

    # To‘g‘ri formatlangan autentifikatsiyalangan proksi URL
    proxy_url = f"http://{proxy_user}:{proxy_pass}@{proxy_ip}:{proxy_port}"
    proxies = {
        "http": proxy_url,
        "https": proxy_url
    }

    try:
        response = requests.post(url, headers=headers, data=raw_json, proxies=proxies, timeout=15)
        response.raise_for_status()
        return response.json()
    except requests.HTTPError as http_err:
        print(f"❌ HTTP xatolik: {http_err} | Status code: {response.status_code}")
        print("Javob:\n", response.text)
    except requests.RequestException as e:
        print("❌ Tarmoq xatoligi:", e)
    finally:
        # Har doim ishlaydigan qism: +1 qo‘shish
        with open("request_count.txt", "r") as file:
            count = int(file.read())
        count += 1
        with open("request_count.txt", "w") as file:
            file.write(str(count))
        
encrypted_e = send_login_request(url, natija, user_agent)
if encrypted_e:
    encrypted_ee = encrypted_e.get("e")
    decrypted_text = decrypt_data(encrypted_ee, key_input)
    print(decrypted_text)