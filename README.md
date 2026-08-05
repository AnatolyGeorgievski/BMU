# BMU
BMU FileParser -- Antminer single &amp; merged BMU parser

Проект включает оригинальный код полного разбора single &amp; merged BMU файлов. 

- [Single & Merged BMU file format](/BMU_format.md)

Сборка проекта CMake:
```sh
$ cmake -B build 
$ cmake --build build
```
Разбор *Merged BMU* архива:
```sh
$ ./build/bmu_parser.exe bin/Antminer-S19-XP-merge-release-20250208020137.bmu bin/bitmain.pub
machine type hash: '9ae16a3b2f90404f'
=== Merge BMU Header ===
magic       : ABABABAB OK
version     : 0
header_size : 36
item_count  : 3
item_size   : 172
data_offset : 16384 (0x4000)
crc32       : 0x8467DBCC OK
#   Model                Hardware             Name            Offset       Size
0   Antminer S19 XP      AMLCtrl_BHB56XXX     update.bmu       16384   15102976
1   Antminer S19 XP      CVCtrl_BHB56XXX      update.bmu    15119360   12696969
2   Antminer S19 XP      zynq7007_BHB56XXX    update.bmu    27816329   20312841
```
Для разбора шифрованного `AMLCtrl` образа используются ключи шифрования `key1` и `key2`. Открытый ключ подписи RSA  `bitmain.pub` берется из прошивки `/etc/bitmain.pub`. Подпись разделов выполняется вторичным ключом `miner.pem`, ключ `miner.pem` подписан первичным ключом `bitmain.pub`.
```sh
$  ./build/bmu_parser.exe Antminer\ S19\ XP/AMLCtrl_BHB56XXX/update.bmu bin/bitmain.pub out -s 'AMLCtrl_BHB56XXX'
machine type hash: 'b0909b8bd8f36bfb'
BMU file 'Antminer S19 XP/AMLCtrl_BHB56XXX/update.bmu'
BMU image type: 'b0909b8bd8f36bfb'
BMU fw version: '20250207'
file[0] type:[9] size:[15100416]
 - magic:       ANDROID!
 - 'kernel'  size:6031360
 - 'ramdisk' size:9035776
 - 'second'  size:30720
 - page      size:2048
 - cmdline: init=/sbin/init
AML encrypted header
 - magic     :AMLSECU!
 - version   :905
 - timestamp :2025020719312667
AML block[0]:
 - data  offset: 0x800
 - raw   length: 0x5C00E7
 - total length: 0x5C0800
header valid
Save file 'out/kernel'
AML block[1]:
 - data  offset: 0x5C1000
 - raw   length: 0x89DB4F
 - total length: 0x89E000
header valid
Save file 'out/ramdisk.img.gz'
AML block[2]:
 - data  offset: 0xE5F000
 - raw   length: 0x6F98
 - total length: 0x7800
header valid
Save file 'out/second.img.gz'
written to out/
File 'datafile' Signature OK!
All Done!
```

Разбор образа для контрольной платы `Zynq7007`:
```sh
$  ./build/bmu_parser.exe Antminer\ S19\ XP/zynq7007_BHB56XXX/update.bmu bin/bitmain.pub out -s 'zynq7007_BHB56XXX'
machine type hash: '059d00a7d35beb11'
BMU file 'Antminer S19 XP/zynq7007_BHB56XXX/update.bmu'
BMU image type: '059d00a7d35beb11'
BMU fw version: '20250207'
file[0] type:[0] size:[2788544]
file[1] type:[1] size:[8014]
file[2] type:[2] size:[4057320]
file[3] type:[3] size:[9170353]
file[4] type:[4] size:[4282957]
file[5] type:[5] size:[552]
file[6] type:[6] size:[1005]
File 'BOOT.bin' Signature OK!
File 'devicetree.dtb' Signature OK!
File 'uImage' Signature OK!
File 'minerfs.image.gz' Signature OK!
File 'update.image.gz' Signature OK!
File 'crl.tar.gz' Signature OK!
File 'miner.btm.tar.gz' Signature OK!
All Done!
```

Разбор образа для контрольной платы `CVCtrl`:
```sh
$  ./build/bmu_parser.exe Antminer\ S19\ XP/CVCtrl_BHB56XXX/update.bmu bin/bitmain.pub out -s 'CVCtrl_BHB56XXX'
machine type hash: '0429c2dc209a8d70'
BMU file 'Antminer S19 XP/CVCtrl_BHB56XXX/update.bmu'
BMU image type: '0429c2dc209a8d70'
BMU fw version: '20250207'
file[0] type:[0] size:[8024422]
file[1] type:[1] size:[2933]
file[2] type:[2] size:[4666542]
File 'BOOT.bin' Signature OK!
File 'devicetree.dtb' Signature OK!
File 'uImage' Signature OK!
All Done!
```

Кроме того, предлагается декомпилированный код утилиты `/usr/bin/FileParser`, входящей в состав дистрибутива и применяемой в процессе обновления прошивки.

Восстановленный парсер [FileParser_recovered.c](/FileParser_restored.c). Файл декомпилирован с использованием IDA Pro 9+ и восстановлен с использованием нейросети Grok и личного опыта разработки. 

```sh
$ gcc -O2 -Wno-deprecated-declarations -o FileParser FileParser_restored.c -lcrypto
$ ./FileParser -s S21 FR-1.6\(260630-S21++\).bmu /etc/bitmain.pub
# file[0] size:[17068544]
# fileName:'/tmp/tmpfw/datafile', size:[17068544]
# fileName:'/tmp/tmpfw/datafile.sig', size:[256]
# All Done!
```

