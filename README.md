# BMU
BMU FileParser -- Antminer single &amp; merged BMU parser

Проект включает оригинальный код полного разбора single &amp; merged BMU файлов. 

Сборка проекта CMake:
```sh
$ cmake -B build 
$ cmake --build build
```


Кроме того, предлагается декомпилированный код утилиты `/usr/bin/FileParser`, входящей в состав дистрибутива и применяемой в процессе обновления прошивки.

Восстановленный парсер [FileParser_recovered.c](FileParser_recovered.c). Файл декомпилирован с использованием IDA Pro 9+ и восстановлен с использованием нейросети Grok и личного опыта разработки. 

```sh
$ gcc -O2 -Wno-deprecated-declarations -o FileParser FileParser_restored.c -lcrypto
$ ./FileParser -s S21 FR-1.6\(260630-S21++\).bmu /etc/bitmain.pub
# file[0] size:[17068544]
# fileName:'/tmp/tmpfw/datafile', size:[17068544]
# fileName:'/tmp/tmpfw/datafile.sig', size:[256]
# All Done!
```

