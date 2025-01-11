# Установщик WireGuard

**Этот проект представляет собой скрипт bash, который направлен на настройку [WireGuard](https://www.wireguard.com/) VPN на сервере Linux!**

Скрипт поддерживает как IPv4, так и IPv6.

## Требования

Поддерживаемые дистрибутивы:

- Debian >= 10
- Ubuntu >= 18.04
И другие...

## Использование

Загрузите и выполните скрипт. Ответьте на вопросы, заданные скриптом, и он позаботится обо всем остальном.

```bash
curl -O https://github.com/xcummins/shell-setup-wireguard/raw/refs/heads/main/wg.sh
chmod +x wg.sh
./wg.sh
```

![image](https://github.com/user-attachments/assets/2449f13a-b836-42fa-a586-9bb44ffdb841)
![image](https://github.com/user-attachments/assets/748e5d4b-d7a2-4c6e-bf7f-a79831ef94f9)
![image](https://github.com/user-attachments/assets/7481a6ce-49ea-421c-9406-e79f7523caff)
![image](https://github.com/user-attachments/assets/8c0e8fed-3d2f-46a0-b928-d8dd0a5393b3)
![image](https://github.com/user-attachments/assets/239f54a8-7669-4b49-af67-e88d7b3859ad)



Он установит WireGuard (модуль ядра и инструменты) на сервер, настроит его, создаст службу systemd и файл конфигурации клиента.

Запустите скрипт еще раз, чтобы добавить или удалить клиентов!
