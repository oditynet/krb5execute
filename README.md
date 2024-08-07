Выполнить программу только в том случае,если тикет получен, тикет валидный и владелец на файл соответвуют владельцу тикета 
Build:
```
g++ krb5client.cpp -lkrb5 -o krb5client
kinit
./krb5client -e /usr/bin/yay 
```
