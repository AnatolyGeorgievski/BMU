# Single & Merged BMU file format

* _Aнатолий Георгиевский_ (https://github.com/AnatolyGeorgievski)

> Неофициальная документация и руководство программиста. 

- [Single \& Merged BMU file format](#single--merged-bmu-file-format)
  - [Merged BMU архив](#merged-bmu-архив)
  - [Структура BMU файла](#структура-bmu-файла)
  - [Проверка подписи файлов](#проверка-подписи-файлов)
  - [Распаковка AMLCtrl образа](#распаковка-amlctrl-образа)
  - [Распаковка zynq7007 образа](#распаковка-zynq7007-образа)
  - [Распаковка u-Boot fitImage](#распаковка-u-boot-fitimage)
  - [Распаковка файлов архива](#распаковка-файлов-архива)

## Merged BMU архив

Формат содержит множество прошивок, собранных для одного типа майнера в один _Merged_ архиве. Прошивки относятся к одной модели (`model`), но различаются по типу оборудования (`hardware`): контрольной плате и версии хеш-платы. Контрольные платы обозначаются строками: `AMLCtrl`, `BBCtrl`, `CVCtrel`, `zynq7007`. Установщик, предположительно, выбирает подходящий образ из архива исходя из оборудования (`hardware`) и версии в графе `timestamp`.

|Offset| Размер | Поле | Содержимое |
|-----|--------|------|------|
|0    | 4 | Magic       | `0xABABABAB`
|4    | 4 | version     | `0`
|8    | 4 | header size | `36`
|12   | 4 | item count  | число записей
|16   | 4 | item size   | размер записи `176` 
|20   | 4 | data offset | смещение сегмента данных
|24   | 4 | CRC32       | контрольная сумма
|28   | 8 | reserved    | `0`

* контрольная сумма CRC32 рассчитывается от всего архива, при расчете и проверке поле CRC32 обнуляется.

Каждая запись представляет собой заголовок отдельного BMU файла с полями: `model`, `hardware`, `chip`, `filename`, `offset`, `size`. При распаковке архива предполагается структура директории вида `{model}/{release-date}/{hardware}/{filename}.bmu`.

В теории иерархия архива может включать разделение по ASIC-чипу на хэш-плате (`chip`). 

## Структура BMU файла

При распаковке выполняется проверка хешей и подписей файлов.
В прошивках Antminer (Security Firmware Update и BMU-пакетах) такая схема:

* Для каждого файла (BOOT.bin, uImage, minerfs.image.gz и т.д.) вычисляется хэш SHA-256.
* Рядом лежит файл .sig (256 байт) — это detached RSA-подпись (PKCS#1 v1.5) этого хэша SHA-256.
* Публичный ключ для проверки подписи берётся из `miner.pem` (он подписан ключом, `/etc/bitmain.pub`).

Распаковщик `/usr/bin/FileParser -s {hardware} {BMU} {bitmain.pub}`  
Проверяет: подпись каждого файла; общую подпись всего пакета (`bmu.sig`).  

|Offset| Размер | Содержимое |
|-----|--------|------------|
|0    | 1 | Magic `0x26`
|2    | 8 | type hash
|11   | 2 | content mask
|13   | 8 | Firmware version
|22   | 2 | длина `miner.pem`
|24   | * | ключ  `miner.pem`
|1048 |256| подпись `miner.pem` RSA 2048-бит.
|1304 | 1 | количество файлов в архиве
|1305 | 4 | заявленный полный размер архива
|1309 |5×i| entry: type + size (BE)
|1360 |256| комментарий к архиву
|…    |…  | данные файлов + их .sig
|-256 |256| RSA-подпись всего пакета

* поле `type hash` содержит хэш от строки `hardware`, по алгоритму _FarmHash64_. Хотя строка  `hardware` является обязательным параметром утилиты `FileParser -s {hardware}`, на практике соответствие не проверяется.

Коды и обозначение файлов в поле _content mask_:
| bit | Файл | Назначение |
|---|------|---|
| 0 |BOOT.bin        | Первый этап загрузчика (FSBL — First Stage Boot Loader). 
| 1 |devicetree.dtb  | Device Tree Blob — описание аппаратной части.
| 2 |uImage          | Linux-ядро в старом формате U-Boot (не FIT). 
| 3 |minerfs.image.gz| Основная rootfs (файловая система майнера). 
| 4 |update.image.gz | ARM Linux RAMDisk Image (gzip compressed). см. `dumpimage -l`
| 5 |crl.tar.gz      | Certificate Revocation List
| 6 |miner.btm.tar.gz| Bitmain-specific
| 7 |reserve         | Bitmain-specific
| 9 |datafile        | Android boot image

## Проверка подписи файлов

Скрипт `/etc/init.d/Update.sh` распаковывает BMU, проверяет подписи:
  
* `/usr/bin/FileParser -s ${hardware} ${BMU} /etc/bitmain.pub` - распаковывает BMU
* `openssl dgst -sha256 -verify  /etc/bitmain.pub -signature miner.pem.sig miner.pem`  
  -- проверка сертификата -- Verified OK
* `openssl dgst -sha256 -verify  /etc/bitmain.pub -signature miner.btm.sig miner.btm`
* `openssl dgst -sha256 -verify  /etc/bitmain.pub -signature crl.sig crl`  
  -- список отозванных сертификатов (уточнить)
* `openssl dgst -sha256 -verify miner.pem -signature ${sigFile} ${file}`  
  -- для каждого файла из дистрибутива

## Распаковка AMLCtrl образа 

Образ содержит файл `datafile` (тип 9) в формате _Android boot image_. Формат содержит расширения AML для безопасного обновления `AMLSECU` с использованием схемы шифрования AES+RSA. 

```sh
$ ./build/bmu_parser.exe bin/FR-1.149\(260702-S21-XP\).bmu bin/bitmain.pub out 
BMU file 'bin/FR-1.149(260702-S21-XP).bmu'
BMU image type: '7eb915d3617c9ca0'
BMU fw version: '20260702'
file[0] type:[9] size:[16822784]
 - magic:       ANDROID!
 - 'kernel'  size:6031360
 - 'ramdisk' size:10758144
 - 'second'  size:30720
 - page      size:2048
 - cmdline: init=/sbin/init
AML encrypted header
 - magic     :AMLSECU!
 - version   :905
 - timestamp :2026070211413325
AML block[0]:
 - data  offset: 0x800
 - raw   length: 0x5C0172
 - total length: 0x5C0800
header valid
Save file 'out/kernel'
AML block[1]:
 - data  offset: 0x5C1000
 - raw   length: 0xA41F3A
 - total length: 0xA42800
header valid
Save file 'out/ramdisk.img.gz'
AML block[2]:
 - data  offset: 0x1003800
 - raw   length: 0x6F98
 - total length: 0x7800
header valid
Save file 'out/second.img.gz'
written to out/
File 'datafile' Signature OK!
All Done!
```

Проверка типов файлов
```sh
$ file datafile
# datafile: Android bootimg, kernel (0x1080000), ramdisk (0x1000000), second stage (0xf00000),
# page size: 2048, cmdline (init=/sbin/init)
$ gzip -d ramdisk.img.gz
$ file ramdisk.img
ramdisk.img: ASCII cpio archive (SVR4 with no CRC)
```

Распаковка образа ramdisk.img.gz:
```sh
$ mkdir ramdisk
$ cd ramdisk
$ gzip -dc ../ramdisk.img.gz | cpio -idmv
```

## Распаковка zynq7007 образа 

Образ содержит файл `BOOT.bin`, в формате _U-Boot fitImage_. Формат содержит _bitstream_ для загрузки FPGA, загрузчик первой стадии FSBL, загрузчик второй стадии - `u-boot.elf`, и конфигурационные файлы в формате Device-Tree blob. Кроме того, в шапке образа содержится таблица векторов прерывания для FSBL и таблица инициализации регистров периферии. Безопасная загрузка выполняется с использованием ключей RSA и опционального шифрования AES. На практике шифрование не применяется. 

Для распаковки `BOOT.bin` и проверки подписей мы используем утилиту [boot_image](/src/zynq_boot.c).

Для контрольной платы `zynq7007` Файл `datafile` (код 9), имеет структуру _U-Boot fitImage_
```sh
$ file datafile
# output/datafile: Device Tree Blob version 17, size=11134020, boot CPU=0, 
# string block size=116, DT structure block size=11132952
$ dumpimage -T flat_dt -l datafile
```

## Распаковка u-Boot fitImage

```sh
$ apt install u-boot-tools
$ dumpimage -T flat_dt -l image.ub
FIT description: U-Boot fitImage Zynq7020 Linux-4.19
Created:         Mon Mar 13 13:27:27 2023
 Image 0 (kernel@1)
  Description:  Linux kernel
  Created:      Mon Mar 13 13:27:27 2023
  Type:         Kernel Image
  Compression:  uncompressed
  Data Size:    3686080 Bytes = 3599.69 KiB = 3.52 MiB
  Architecture: ARM
  OS:           Linux
  Load Address: 0x00008000
  Entry Point:  0x00008000
  Hash algo:    sha1
  Hash value:   cba4c985c443d392a2e77f58bc296630af524f1b
 Image 1 (fdt@system.dtb)
  Description:  Flattened Device Tree blob
  Created:      Mon Mar 13 13:27:27 2023
  Type:         Flat Device Tree
  Compression:  uncompressed
  Data Size:    8207 Bytes = 8.01 KiB = 0.01 MiB
  Architecture: ARM
  Hash algo:    sha1
  Hash value:   c809918eb1764070273197de139ddfdcfa5803c6
 Image 2 (ramdisk@1)
  Description:  Ramdisk Image
  Created:      Mon Mar 13 13:27:27 2023
  Type:         RAMDisk Image
  Compression:  gzip compressed
  Data Size:    15428776 Bytes = 15067.16 KiB = 14.71 MiB
  Architecture: ARM
  OS:           Linux
  Load Address: unavailable
  Entry Point:  unavailable
  Hash algo:    sha1
  Hash value:   198fa38c94388df076cbd172208a26fc8633f355
 Default Configuration: 'conf@system.dtb'
 Configuration 0 (conf@system.dtb)
  Description:  1 Linux kernel, FDT blob, ramdisk
  Kernel:       kernel@1
  Init Ramdisk: ramdisk@1
  FDT:          fdt@system.dtb
  Hash algo:    sha1
  Hash value:   unavailable
```
Каждый элемент архива извлекаем по индексу
```sh
$ dumpimage -T flat_dt image.ub -p 0 -o kernel
$ dumpimage -T flat_dt image.ub -p 1 -o system.dtb
$ dumpimage -T flat_dt image.ub -p 2 -o ramdisk.cpio.gz
$ dtc -o system.dts -O dts system.dtb
$ mkdir ramdisk
$ cd ramdisk
$ gzip -dc ../ramdisk.cpio.gz | cpio -idmv
```

## Распаковка файлов архива

Для идентификации файлов используются: `file`, `hexdump`.  
Для распаковки используются утилиты из дистрибутива Debian/Ubuntu:
* `dumpimage`, `gzip`, `cpio`, `dtc`

После распаковки BMU:
```plain
  #    Code  Name                Offset     Size
---  ------  ----------------  --------  -------
  0       0  BOOT.bin              2048  2788544
  1       1  devicetree.dtb     2790592     8014
  2       2  uImage             2798606  4057320
  3       3  minerfs.image.gz   6855926  8373297
  4       4  update.image.gz   15229223  4281968
  5       5  crl.tar.gz        19511191      552
  6       6  miner.btm.tar.gz  19511743     1804
```

**Распаковка _update.image_**  

```sh
$ file update.image.gz
update.image.gz: u-boot legacy uImage, ramdisk, Linux/ARM, RAMDisk Image (gzip)

$ dumpimage -l  update.image.gz
Image Name:   ramdisk
Created:      Sat Apr 11 15:26:20 2026
Image Type:   ARM Linux RAMDisk Image (gzip compressed)
Data Size:    4281904 Bytes = 4181.55 KiB = 4.08 MiB
Load Address: 00000000
Entry Point:  00000000

$ dumpimage -T ramdisk update.image.gz -p 0 -o update-ramdisk.gz
$ gzip -d update-ramdisk.gz
$ file update-ramdisk
update-ramdisk: Linux rev 0.0 ext2 filesystem data, UUID=00000000-0000-0000-0000-000000000000, volume name "linux"
$ mkdir update
$ mount -o loop -t ext2 update-ramdisk update
```

Образ распакован и смонтирован в папку `update`. Аналогично раскрывается образ `minerfs.image`.
```sh
$ dumpimage -T ramdisk minerfs.image.gz -p 0 -o minerfs-ramdisk.gz
$ gzip -d minerfs-ramdisk.gz
$ mkdir minerfs
$ mount -o loop -t ext2 minerfs-ramdisk minerfs
```
