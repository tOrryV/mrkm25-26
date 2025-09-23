# Signature Service (Lab)

Мінімалістичний HTTP‑сервіс на **FastAPI**, який генерує ключі/сертифікати та створює/перевіряє **CMS (PKCS#7)** підписи через **OpenSSL 3**.

---

## Зміст

- [Можливості](#можливості)
- [Вимоги](#вимоги)
- [Встановлення та запуск](#встановлення-та-запуск)
- [Швидкий старт](#швидкий-старт)
- [Тестування через Swagger UI](#тестування-через-swagger-ui)
- [Структура проєкту](#структура-проєкту)
- [Загальне пояснення коду](#загальне-пояснення-коду)
- [Ключові функції та ендпоїнти](#ключові-функції-та-ендпоїнти)
- [Нотатки з безпеки](#нотатки-з-безпеки)
- [Налагодження та типові помилки](#налагодження-та-типові-помилки)
- [FAQ](#faq)

---

## Можливості

- Генерація ключових пар: **RSA**, **ECDSA**, **Ed25519**.
- Випуск **самопідписаного** сертифіката (лабораторний режим).
- Експорт у **PKCS#12 (.p12)** з паролем.
- Підпис **CMS (PKCS#7)** в режимах **attached** та **detached** з SHA‑256/384/512.
- Перевірка CMS‑підпису (без валідації довірчого ланцюга; лише коректність підпису — для лабораторії).
- Простий REST API + інтерактивна документація **Swagger** на `/docs`.

---

## Вимоги

- **Python 3.10+**
- **OpenSSL 3.x** (саме 3, не LibreSSL)
- macOS/Linux/WSL (Windows — через WSL або попередньо встановити OpenSSL 3)

> ℹ️ На macOS за замовчуванням може бути LibreSSL. Потрібно встановити `openssl@3` через Homebrew і вказати шлях у `OPENSSL_BIN`.

---

## Встановлення та запуск

### 1) Клонування та віртуальне середовище

```bash
git clone <your-repo-url> signature-service
cd signature-service
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
```

### 2) Залежності Python

```bash
pip install --upgrade pip
pip install fastapi uvicorn pydantic
```

### 3) Встановлення OpenSSL 3

- **macOS (Homebrew):**
  ```bash
  brew install openssl@3
  export OPENSSL_BIN=$(brew --prefix openssl@3)/bin/openssl
  echo 'export OPENSSL_BIN=$(brew --prefix openssl@3)/bin/openssl' >> ~/.zshrc  # опційно
  ```
- **Linux:** переконайтеся, що `openssl` версії 3.x доступний у PATH, або вкажіть `OPENSSL_BIN`.

### 4) Запуск сервісу

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Перевірка: відкрийте `http://localhost:8000/docs` — має завантажитись Swagger UI.

---

## Швидкий старт

### 1) Створення ключа та сертифіката

```bash
curl -s -X POST http://localhost:8000/v1/keys/generate \
  -H 'Content-Type: application/json' \
  -d '{
    "algo": "RSA",
    "keySize": 2048,
    "protection": "PKCS12",
    "label": "signing-key-01",
    "subject": "CN=Demo User,O=Org,C=UA",
    "exportCert": true,
    "pkcs12_password": "changeit"
  }' | jq .
```

Відповідь міститиме `keyId` (напр. `k_ab12cd34`) та PEM‑тексти публічного ключа й сертифіката.

### 2) Підписання даних (attached)

```bash
# Підготуємо base64 вміст ("Hello")
DATA_B64="SGVsbG8="
KEY_ID="<keyId з попереднього кроку>"

curl -s -X POST http://localhost:8000/v1/sign \
  -H 'Content-Type: application/json' \
  -d "{\
    \"keyId\": \"$KEY_ID\",\
    \"signMode\": \"attached\",\
    \"hashAlg\": \"SHA256\",\
    \"content\": \"$DATA_B64\"\
  }" | jq .
```

Отримаєте поле `cms` — це **base64** DER‑кодування CMS підпису.

### 3) Перевірка підпису (attached)

```bash
CMS_B64="<скопіюйте cms з попереднього кроку>"

curl -s -X POST http://localhost:8000/v1/verify \
  -H 'Content-Type: application/json' \
  -d "{\
    \"cms\": \"$CMS_B64\"\
  }" | jq .
```

Очікувана відповідь:

```json
{
  "isValid": true,
  "signers": [
    { "subject": "Demo User", "alg": "sha256WithRSAEncryption", ... }
  ],
  "warnings": []
}
```

> Для **detached** підпису викликайте `/v1/sign` з `signMode=detached`, а при верифікації додайте `detachedContent` (base64 початкових даних).

---

## Тестування через Swagger UI

Swagger UI доступний за адресою [`/docs`](http://localhost:8000/docs). Це інтерактивний playground для всіх ендпоїнтів:

1. **Відкрийте** `http://localhost:8000/docs` у браузері.
2. Ви побачите список ендпоїнтів (`/v1/keys/generate`, `/v1/sign`, `/v1/verify`).
3. Для кожного ендпоїнта можна:
   - Натиснути **Try it out**.
   - Ввести JSON‑тіло запиту.
   - Натиснути **Execute** й одразу отримати відповідь від сервера.

### Приклад у Swagger:

- `/v1/keys/generate` → натискаєте **Try it out**, редагуєте поля (наприклад, `algo=RSA`, `subject=CN=Demo User,O=Org,C=UA`) → **Execute**.
- `/v1/sign` → вводите `keyId` з попереднього кроку та `content` у base64.
- `/v1/verify` → вставляєте отримане значення `cms`.

Swagger автоматично відобразить **request** та **response**, що зручно для налагодження й навчання.

---

## Структура проєкту

```
.
├── main.py           # Увесь застосунок FastAPI
└── state/            # Створюється автоматично
    ├── keys/         # Приватні ключі (.pem) + .p12
    └── certs/        # Самопідписані сертифікати (.crt.pem)
```

---

## Загальне пояснення коду

Файл **`main.py`** описує веб‑сервіс з трьома основними можливостями:

1. **Генерація ключа/сертифіката** (`POST /v1/keys/generate`) — через `openssl genpkey`, `req`, `x509`, з подальшим експортом у `.p12`.
2. **Підписання даних** (`POST /v1/sign`) — через `openssl cms -sign` у форматі DER (**attached** або **detached**), відповідь повертається у base64.
3. **Перевірка** (`POST /v1/verify`) — через `openssl cms -verify` з прапорцями `-noverify -no_attr_verify` (лабораторний режим, без перевірки ланцюга довіри).

Стан (ключі/сертифікати) зберігається локально в `./state/keys` та `./state/certs`. На старті сервіс перевіряє доступність **OpenSSL 3**.

---

## Ключові функції та ендпоїнти

### Конфіг та моделі

- **`OPENSSL_BIN`** — шлях до виконуваного `openssl`. Береться з `ENV`, потім з `PATH`, інакше типовий Homebrew‑шлях.
- **Pydantic‑моделі**: `KeyGenRequest`, `KeyGenResponse`, `SignRequest`, `SignResponse`, `VerifyRequest`, `VerifyResponse` — описують контракт API.

### Хелпери

- **`run(cmd, input_bytes=None)`**

  - Обгортає `subprocess.run`, повертає `stdout` або кидає HTTP 400 з текстом помилки OpenSSL.
  - Централізує обробку CLI‑помилок.

- **`ensure_openssl()`**

  - Викликається на `startup`. Переконується, що встановлено **OpenSSL 3.x** (часто на macOS у системі лише LibreSSL).
  - Якщо версія не 3.x — HTTP 500 з підказкою встановлення через Homebrew та налаштування `OPENSSL_BIN`.

- **`b64decode_to_file(b64, path)`**** / ****`file_to_b64(path)`**

  - Безпечне перетворення між base64 та файлами.

- **`key_paths(key_id)`**

  - Єдине місце, де визначається файловий макет артефактів (priv/publ/cert/p12) для заданого `keyId`.

### `POST /v1/keys/generate` → `generate_keys(req)`

- Створює тимчасову директорію, генерує **priv.pem**, витягає **pub.pem**, формує CSR та самопідписаний **cert.pem** (365 днів).
- Підтримує **RSA** (`keySize`), **ECDSA** (`curve`, напр. `secp256r1`), **Ed25519\`**.
- Зберігає артефакти в `./state/keys` та `./state/certs`.
- Експортує `.p12` з міткою `label` і паролем `pkcs12_password`.
- Повертає `keyId` (використовуйте далі для підпису), опційно PEM‑сертифікат і публічний ключ.

### `POST /v1/sign` → `sign(req)`

- Шукає приватний ключ і сертифікат за `keyId`.
- Готує вхідні дані з `content` (base64 → bytes → файл).
- Команда `openssl cms -sign` з прапорцями:
  - загальні: `-binary -signer cert -inkey key -outform DER -md <sha256|sha384|sha512>`
  - **attached**: додає `-nodetach`
  - **detached**: додає `-detached`
- Повертає **DER** CMS у base64 поле `cms`.

### `POST /v1/verify` → `verify(req)`

- Приймає CMS (base64 DER). Для **detached** — ще й `detachedContent` (base64).
- Викликає `openssl cms -verify -binary -inform DER` і зберігає вивід у тимчасовий файл.
- **Лабораторний режим**: прапорці `-noverify -no_attr_verify` вимикають перевірку довірчого ланцюга та атрибутів, перевіряється лише криптографічна коректність підпису.
- `isValid=true/false` залежно від успіху команди. `warnings[]` містить тексти помилок OpenSSL (якщо були).
- Додатково через `openssl cms -cmsout -print` best‑effort витягається суб’єкт і алгоритм підпису для `signers[]`.

---

## Нотатки з безпеки

- **Самопідписаний** сертифікат придатний тільки для лабораторних/тестових цілей. У проді використовуйте CA/PKI та повну перевірку ланцюга.
- `.p12` і приватні ключі лежать у **файловій системі** сервера. Для прод‑рішень використовуйте HSM/Cloud KMS або секрет‑сховище.
- Не зберігайте пароль `pkcs12_password` у відкритому вигляді в репозиторії/логах.
- Обмежуйте доступ до `./state/` (права на файли/директорію, ізоляція контейнером).
- Додавайте **rate limiting** та аутентифікацію до API, якщо сервіс публічний.

---

## Налагодження та типові помилки

- `OpenSSL not available` / `Need OpenSSL 3.x. Detected: LibreSSL ...` — встановіть `openssl@3` та виставте `OPENSSL_BIN`.
- `OpenSSL error: ...` при підписі/перевірці — перевірте коректність base64, режимів (`attached`/`detached`) і відповідність `detachedContent` оригінальним даним.
- `keyId ... not found` — перед підписом згенеруйте ключ (`/v1/keys/generate`) і використовуйте повернутий `keyId`.

---

## FAQ

**Чому саме DER + base64, а не PEM?**\
OpenSSL CMS зручно повертати у **DER**, а для транспорту ми кодуємо в base64. Це зменшує неоднозначності форматів і спрощує клієнтам десеріалізацію.

**Чи можна змінити термін дії сертифіката?**\
Так, у `generate_keys` параметр `-days 365` можна винести у конфіг або зробити полем запиту.

**Чи перевіряється ланцюг довіри при /v1/verify?**\
Ні, у лабораторному режимі ні. Для прод‑режиму приберіть `-noverify`, додайте `-CAfile`/`-CApath` і повну валідацію CRL/OCSP.

---
