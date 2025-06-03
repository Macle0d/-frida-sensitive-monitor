# Frida Sensitive Monitor

Script de Frida para detectar datos sensibles en aplicaciones Android. Engancha funciones que manipulan `String` y `SecretKeySpec` para identificar posibles claves, tokens, contraseñas y otros datos críticos.

## 📜 Descripción

Este script intercepta:

- Constructores de `String` que reciben `byte[]` o `String`
- Constructores de `SecretKeySpec` para claves criptográficas

Y detecta patrones como:

- JWT
- Claves AWS
- Tarjetas de crédito
- Contraseñas
- Hashes (SHA, bcrypt, Argon2)
- Claves codificadas en Base64/Base32
- Device IDs, OTPs, etc.

## 🚀 Uso

1. Conecta tu dispositivo Android con `adb`
2. Inicia la app objetivo
3. Ejecuta el script con Frida:

```bash
frida -U -n com.ejemplo.app -l monitor_universal.js

## Autor

- Omar Peña - [@Macle0d](https://github.com/Macle0d) - [@p3nt3ster](https://x.com/p3nt3ster)
