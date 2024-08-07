Выполнить программу только в том случае,если тикет получен и права й файла соответвуют тикету
Build:
```
g++ krb5client.cpp -lkrb5 -o krb5client
kinit
./krb5client -e /usr/bin/yay 
```
