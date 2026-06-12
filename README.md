# Secure Messenger — демонстрация Security CI

Учебный проект: бэкенд простого мессенджера на **Java (чистый JDK)** с REST-подобным
API, к которому подключён **CI-конвейер на GitHub Actions**, проверяющий код статическим
анализатором уязвимостей **OWASP Top 10:2025 — A04 (Cryptographic Failures)** и
**A07 (Authentication Failures)**.

Анализатор — это headless-версия (CLI) расширения VS Code «OWASP Security Checker»
с тем же ядром (AST + regex + ML-подавление ложных срабатываний). Исходники сканера
лежат в [tools/security-scanner/](tools/security-scanner/).

## Что демонстрируется

CI **бракует** коммит (красный ✗), если в коде есть находка уровня **HIGH или CRITICAL**,
и **пропускает** (зелёный ✓), когда таких находок не осталось. Уровни `medium`/`low`
показываются в отчёте, но сборку не валят (порог задаётся флагом `--fail-on`).

Сценарий из трёх коммитов описан в [COMMITS.md](COMMITS.md):

| Коммит | Состояние кода | Результат CI |
|--------|----------------|--------------|
| 1 | MD5-хеш паролей, `new Random()`, хардкод-секрет, HTTP-URL | ✗ **брак** (2 critical, 1 high) |
| 2 | Исправлены MD5 и секрет, но `new Random()` остался | ✗ **брак** (1 high) |
| 3 | Токены через `SecureRandom`, HTTPS | ✓ **проходит** |

## API мессенджера

```
POST /api/register   {"user":"alice","password":"..."}
POST /api/login      {"user":"alice","password":"..."}   -> {"token":"..."}
POST /api/messages   {"to":"bob","text":"hi"}              (заголовок Authorization: Bearer <token>)
GET  /api/messages                                          (Authorization: Bearer <token>)
```

## Локальный запуск

```bash
# собрать и запустить бэкенд
javac -d backend/out $(find backend/src -name '*.java')
java -cp backend/out com.example.messenger.MessengerServer 8080

# собрать сканер и проверить код (как в CI)
cd tools/security-scanner && npm install && npm run build && cd ../..
node tools/security-scanner/dist/cli.js backend/src --fail-on high
```

## Как работает CI

[.github/workflows/security.yml](.github/workflows/security.yml) на каждый push/PR:

1. **build-backend** — компилирует Java (`javac`);
2. **security-scan** — собирает сканер, запускает его по `backend/src`, формирует отчёт
   **SARIF** (виден в *Security → Code scanning*) и **падает** при находке ≥ HIGH.
