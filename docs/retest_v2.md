# Re-test - Verificare fix-uri pe varianta securizata (v2)

Ruleaza aplicatia v2 pe portul 5001.

```bash
cd ~/DASS/fixed
python3 app.py
```

## 1. Password policy (4.1)

```bash
curl -i -X POST http://127.0.0.1:5001/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com","password":"123"}'
```

Rezultat asteptat:
- `400 Password policy failed`

## 2. Register cu parola puternica

```bash
curl -i -X POST http://127.0.0.1:5001/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com","password":"StrongPass!2026"}'
```

Rezultat asteptat:
- 201 Created

## 3. User enumeration blocat (4.4)

```bash
curl -i -X POST http://127.0.0.1:5001/login \
  -H "Content-Type: application/json" \
  -d '{"username":"no_such_user","password":"x"}'
```

```bash
curl -i -X POST http://127.0.0.1:5001/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"WrongPass!1"}'
```

Rezultat asteptat:
- acelasi mesaj: `Invalid credentials`

## 4. Brute force limitat (4.3)

Executa 6 incercari gresite:

```bash
for i in {1..6}; do
  curl -s -X POST http://127.0.0.1:5001/login \
    -H "Content-Type: application/json" \
    -d '{"username":"alice","password":"WrongPass!1"}'
done
```

Apoi incearca parola corecta imediat:

```bash
curl -i -X POST http://127.0.0.1:5001/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"StrongPass!2026"}'
```

Rezultat asteptat:
- cont temporar blocat / raspuns invalid generic

## 5. Sesiune hardenizata (4.5)

```bash
curl -i -c cookies_v2.txt -X POST http://127.0.0.1:5001/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"StrongPass!2026"}'
```

Rezultat asteptat:
- cookie `HttpOnly`
- `SameSite=Strict`
- expirare redusa
- token random, nu predictibil

## 6. Reset parola securizat (4.6)

Genereaza token:

```bash
curl -i -X POST http://127.0.0.1:5001/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"username":"alice"}'
```

Foloseste token o singura data:

```bash
curl -i -X POST http://127.0.0.1:5001/reset-password \
  -H "Content-Type: application/json" \
  -d '{"token":"<TOKEN_PRIMIT>","new_password":"NewStrong!2026"}'
```

Repeta cu acelasi token.

Rezultat asteptat:
- prima cerere merge
- a doua cerere esueaza (`Invalid or expired token`)

## 7. Verificare stocare parola in DB (4.2)

```bash
python3 - << 'PY'
import sqlite3
conn = sqlite3.connect('authx_fixed.db')
rows = conn.execute('SELECT id, username, password_hash FROM users').fetchall()
for row in rows:
    print(row)
conn.close()
PY
```

Rezultat asteptat:
- doar hash, fara parole in clar

## Evidenta pentru raport

Include capturi pentru fiecare test + concluzie "atac blocat".
