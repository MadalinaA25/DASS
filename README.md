# AuthX - Break the Login (Build, Hack & Secure)

Acest proiect livreaza doua versiuni clare:
- `vulnerable/` (v1): implementare intentionat vulnerabila
- `fixed/` (v2): implementare securizata, cu fix-uri mapate pe cerintele 4.1-4.6

Tehnologii:
- Python
- Flask
- SQLite (DB reala, locala)

## 1. Structura proiect

- `vulnerable/app.py` - varianta vulnerabila
- `fixed/app.py` - varianta reparata
- `docs/raport_final.md` - raportul proiectului
- `screenshots/` - dovezi vizuale pentru demonstratii
- link video: 

## 2. Rulare rapida

### 2.1 Cerinte

- Python 3.10+
- pip

### 2.2 Instalare dependinte

```powershell
cd "d:\proiecte an 4\DASS"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r .\vulnerable\requirements.txt
pip install -r .\fixed\requirements.txt
```

### 2.3 Pornire v1 (vulnerable)

```powershell
cd "d:\proiecte an 4\DASS\vulnerable"
python .\app.py
```

Server: `http://127.0.0.1:5000`

### 2.4 Pornire v2 (fixed)

```powershell
cd "d:\proiecte an 4\DASS\fixed"
python .\app.py
```

Server: `http://127.0.0.1:5001`

## 3. Endpoint-uri principale (ambele versiuni)

- `POST /register`
- `POST /login`
- `POST /logout`
- `POST /forgot-password`
- `POST /reset-password`
- `GET /me`
- `POST /tickets`
- `GET /tickets/<id>`
- `GET /health`

Endpoint suplimentar in v2:
- `GET /audit` (doar rol MANAGER)

## 4. Mapping vulnerabilitati -> fix-uri

### 4.1 Password policy slab
- v1: accepta parole triviale
- v2: minim 10 caractere + upper + lower + cifra + caracter special

### 4.2 Stocare nesigura a parolelor
- v1: parole in clar (`password_plaintext`)
- v2: hash modern `scrypt` (`werkzeug.generate_password_hash`)

### 4.3 Brute force / lipsa rate limiting
- v1: nelimitat
- v2: lock temporar cont dupa 5 incercari gresite + limitare burst pe IP

### 4.4 User enumeration
- v1: mesaje diferite (`User does not exist` vs `Wrong password`)
- v2: mesaj unic `Invalid credentials` + raspuns cu timp uniform

### 4.5 Gestionare nesigura sesiuni
- v1: token predictibil (`username-timestamp`), cookie fara flags securitate
- v2: token random, stocat hash-uit, expirare scurta, rotatie la login, invalidare la logout,
  cookie cu `HttpOnly`, `SameSite=Strict`, `Secure` configurabil (`COOKIE_SECURE=1`)

### 4.6 Resetare parola nesigura
- v1: token predictibil (`reset-<id>`), reutilizabil, fara expirare
- v2: token random one-time, expirare 10 minute, invalidare dupa folosire

