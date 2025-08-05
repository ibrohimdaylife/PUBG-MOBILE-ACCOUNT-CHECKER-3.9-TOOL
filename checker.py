#developer : @ibrohim_Daylife
#if you fix problem, please let me know


from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import sys
import requests
import time
import hashlib
import string
import random
import base64
from Crypto.Cipher import AES
import json
from Crypto.Util.Padding import unpad
from Crypto.Util.Padding import pad

randstr_input = input("🌀 randstr ni kiriting (masalan: @lu86i4s5bhj): ").strip()
ticket_input = input("🎫 ticket ni kiriting (masalan: terror_1001_2033864629_1753759516): ").strip()

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

#current_ms_nano = "17540435951425927247"
current_ms_nano = get_nanoseconds()
current_ms = int(str(current_ms_nano)[:13]) + random.randint(126, 363)
current_ts = str(current_ms_nano)[:10]
n_value = str(current_ms_nano)[-10:]

def generate_md5_hashed_code(current_ms):
    prefix = "288f02a1-0ae2-4246-8bb8-5262f52cc222"
    suffix = "mqF74IPfly2hREYG"
    full_string = f"{prefix}{current_ms}{suffix}"
    md5_hash = hashlib.md5(full_string.encode()).hexdigest()
    #print(md5_hash)
    return full_string, md5_hash

def generate_n():
    raw = random.randint(-2**31, 2**31 - 1)
    return abs(raw)

def md5_hash_password(text):
    return hashlib.md5(text.encode()).hexdigest()

def bytes_to_base64url(b):
    base64_str = base64.b64encode(b).decode('utf-8')
    return base64_str.replace('+', '-').replace('/', '_').rstrip('=')

with open("request_count.txt", "r") as file:
    request_count = int(file.read())

def build_login_request(current_ms_nano, current_ms, current_ts, n_value, randstr_input, ticket_input):

    email = input("✉️  Email kiriting: ").strip()
    password_plain = input("🔑 Parol kiriting: ").strip()
    #email = "vvxonys@telegmail.com"
    #password_plain = "asdfgh77"
    password_hashed = md5_hash_password(password_plain)
    
    current_ms_2 = int(current_ms) + 1  # dinfo uchun boshqa timestamp

    full_string, md5_value = generate_md5_hashed_code(current_ms_nano)

    # Eslatma: Android \/ API-28 bu joyda to'g'ri escape qilingan!
    dinfo = f"1|43405|SM-N975F|en|3.9.0|{current_ms_2}|2.25|1920*1080|samsung|23892eabf941a0b0728901325f0a9c4f|arm64-v8a+x86_64|Android \\/ API-28(samsung-user 9.0.0 20171130.276299 release-keys)"

    request = (
        f"/account/login?account_plat_type=3&appid=dd921eb18d0c94b41ddc1a6313889627"
        f"&lang_type=en_US&os=1&s=1&seq=1320-288f02a1-0ae2-4246-8bb8-5262f52cc222-{current_ms}-13&v=1"
        f"{{\"account\":\"{email}\",\"account_type\":1,\"area_code\":\"\",\"password\":\"{password_hashed}\","
        f"\"qcaptcha\":{{\"ret\":0,\"msg\":\"success\",\"randstr\":\"{randstr_input}\",\"ticket\":\"{ticket_input}\"}},"
        f"\"sid\":2210147060974317505,\"pticket\":\"\",\"did\":\"288f02a1-0ae2-4246-8bb8-5262f52cc222\","
        f"\"dinfo\":\"{dinfo}\","
        f"\"sGuestId\":\"23892eabf941a0b0728901325f0a9c4f\",\"sOriginalId\":\"23892eabf941a0b0728901325f0a9c4f\","
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
email, password_hashed, dinfo, current_ts, n_value, md5_hash_build = build_login_request(current_ms_nano, current_ms, current_ts, n_value, randstr_input, ticket_input)

def build_encryption_plaintext(email, password_hashed, dinfo, ts, n, md5_hash_build, randstr_input, ticket_input):
    return (
        f'{{"account":"{email}","account_type":1,"area_code":"","password":"{password_hashed}",'
        f'"qcaptcha":{{"ret":0,"msg":"success","randstr":"{randstr_input}","ticket":"{ticket_input}"}},'
        f'"sid":2210147060974317505,"pticket":"","did":"288f02a1-0ae2-4246-8bb8-5262f52cc222",'
        f'"dinfo":"{dinfo}","sGuestId":"23892eabf941a0b0728901325f0a9c4f","sOriginalId":"23892eabf941a0b0728901325f0a9c4f",'
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
        f"&lang_type=en_US&os=1&s=1&seq=1320-288f02a1-0ae2-4246-8bb8-5262f52cc222-{current_ms}-13&v=1"
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

def send_login_request(url: str, natija: str):
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
        
encrypted_e = send_login_request(url, natija)
encrypted_ee = encrypted_e.get("e")
decrypted_text = decrypt_data(encrypted_ee, key_input)
print(decrypted_text)