% akrypt(1) Русский мануал для программы akrypt
%
% 18 июля 2019 г.

# НАЗВАНИЕ

akrypt - консольная утилита для выполнения криптографических преобразований.

# СИНТАКСИС

Синтаксис выполнения программы

akrypt команда [*опции*] [*файл* или *каталог*] ...

# ОПИСАНИЕ

Утилита предназначена для работы с ключами и криптографическими преобразованиями,
реализуемыми библиотекой *libakrypt*, включая контроль целостности файлов, шифрование данных,
а также функции для работы с ключевой информацией.

Каждая команда определяет отдельный класс криптографических преобразований и функциональных
возможностей программы. В настоящее время доступны следующие команды:

*icode* Вычисление контрольной суммы или имитовставки для заданного файла

*show*  Вывод служебной и справочной информации

Получить подробную информацию о доступных опциях и параметрах любой команды можно с помощью вызова

    akrypt команда --help


# КОМАНДЫ ДЛЯ КОНТРОЛЯ ЦЕЛОСТНОCТИ

## i [*опции*] *файл* или *каталог*

Короткая форма команды *icode*.

## icode [*опции*] *файл* или *каталог*

Команда icode позволяет вычислять контрольные суммы или имитовставки для одного или нескольких файлов.
В случае указания в командной строке имени каталога, контрольные суммы или имитовставки будут подсчитаны для всех
доступных для чтения файлов в указанном каталоге.

При вычислении имитовставки должен быть использован секретный ключ. Данный ключ должен быть создан заранее,
либо выработан из заданного пользователем пароля.

В настоящий момент доступны следующие опции.

\-a, \--algorithm <*ni*>
: Опция позволяет указать задаваемый параметром *ni* (name or identifier) алгоритм, который будет
использован для вычисления контрольной суммы или имитовставки.
В случае, когда опция не определена, для вычисления контрольной суммы используется функция хеширования
"Стрибог256", регламентированная национальным стандартом ГОСТ Р 34.11-2012.
Получить перечень всех доступных алгоритмов можно с помощью команды *show*, см. ниже.

\
: При вычислении имитовставок обязательно использование секретного ключа.
Поскольку некоторые алгоритмы накладывают ограничения на объем информации, обрабатываеой на одном ключе,
то для таких алгоритмов вычисление имитоставок от длинных (больших) файлов может быть недоступно.
В этом случае вместо имитовставки выводится значение *skipped*.
Если Вам необходимо вычислять имитовставки файлов с произвольной, сколь угодно большой длиной,
то используйте следующие алгоритмы: *hmac-streebog256* и *hmac-streebog512*.

\-c,  \--check <*file*>
: Опция позволяет проверить контрольные суммы или имитовставки для одного или нескольких файлов.
Данные суммы должны быть вычислены заранее и сохраненны в файле *file*.
Если при проверке используется алгоритм, отличный от установленного по-умолчанию,
необходимо указать его имя или идентификатор с помощью опции *-a*.

\-o, \--output <*file*>
: Опция определяет имя файла, в который записываются вычисленные значения контрольных сумм или имитовставок.
Данный файл может быть указан в качестве параметра опции *-c*.

\-p
: Опция указывает, что для выработки секретного ключа,
используемого при вычислении или проверке имитовставки от одного или нескольких файлов,
должен использоваться задаваемый пользователем пароль.
Если опция *password* не опредена, то программа предлагает пользователю ввести пароль с консоли.

\--password <*pass*>
: Опция в явном виде указывает, что для выработки секретного ключа должен
использоваться пароль, определяемый последовательностью символов *pass*.
Использование данной опции не является безопасным.

\-r, \--recursive
: Опция указывает, что при вычислении контрольных сумм или имитовставок,
должна выполняться рекурсивная процедура обхода текущего и всех вложенных каталогов.

\--reverse-order
: Опция указывает, что все выводимые и вводимые последовательности октетов,
должны обрабатываться в обратном порядке. Использование данной опции целесообразно
для вывода результатов в big endian порядке следования октетов.

\--tag
: Опция указывает, что значения контрольных сумм или имитовставок должны выводиться в формате,
принятом в операционных системах семейства BSD. В таком формате
указывается не только имя файла и его контрольная сумма, но и алгоритм, с помощью которого данная сумма была подсчитана.

\-t, \--template
: Опция указывает шаблон поиска файлов. Для задания шаблона
используются правила, аналогичные правилам, определенным для функции *fnmatch*.

Следующие опции имеет смысл применять только при проверке контрольных сумм или имитовставок.

\--dont-show-stat
: Опция запрещает вывод в консоль статистической информации об общем количестве проверенных файлов,
количестве успешных или неуспешных проверок и т.п.

\--ignore-errors
: Опция запрещает останавливать процесс проверки контрольных сумм или имитовставок в случае возникновения ошибок
доступа или чтения файлов, отсутствия файлов, содержащихся в списке и т.п.


\--quiet
: Опция запрещает вывод символов "Ok" после успешной проверки контрольной суммы.

\--status
: Опция запрещает вывод какой-либо информации при проверке контрольных сумм. Результат проверки
возвращается в коде возврата программы (любое отличное от нуля значение сигнализирует об ошибке).


# ВСПОМОГАТЕЛЬНЫЕ И ИНФОРМАЦИОННЫЕ КОМАНДЫ

## show [*опции*]

Команда позволяет получить информацию о доступных криптографических преобразованиях, значениях
технических и криптографических характеристик, параметрах библиотеки по-умолчанию.
В настоящий момент доступны следующие опции.

\--engines
:   Опция позволяет вывести список всех типов криптографических механизмов, которые могут быть
использованы в приложениях библиотеки libakrypt. К таким типам, например, относятся блочные шифры
или алгоритмы выработки имитовставки.

\--modes
:   Опция позволяет вывести список всех режимов криптографических преобразований,
которыми могут быть охарактеризованы криптографические преобразования. При этом одному криптографическому
механизму может соответствовать несколько режимов. Например, собственно функция хэширования имеет режим algorithm,
а ее параметры - kbox params.

\--oids
:   Опция позволяет вывести список всех доступных криптографических механизмов. Каждый механизм
идентифицируется свои именем, которое используется для его указания пользователем и/или последовательностью
чисел, разделенных точками. Последняя последовательность называется Object IDentifier (OID) и используется
при автоматизированной обработке данных. Например, среди прочих,
будет выведена следующая информация об алгоритме блочного шифрования Магма

    *magma*        block cipher     algorithm   1.2.643.7.1.1.5.1

    в которой *magma* является именем криптографического механизма, а 1.2.643.7.1.1.5.1 - его идентификатором.

\--oid <*eni*>
:   Опция принимает в качестве параметра произвольную строку символов *eni* (engine, name or identifier)
и выводит все доступные криптографические механизмы, в именах или идентификаторах которых
содержится указанная строка. Например, вызов

    akrypt show --oid magma

    может привести к следующему переченю криптографических механизмов.

    *omac-magma*   omac function    algorithm   1.2.643.2.52.1.4.1

    *mgm-magma*    mgm function     algorithm   1.2.643.2.52.1.4.3

    *magma*        block cipher     algorithm   1.2.643.7.1.1.5.1

\--options
: Опция выводит перечень всех криптографических параметров библиотеки. К указанным парметрам относятся,
например, число блоков информации, которые могут быть зашифрованы на одном ключе, или число итераций алгоритма
PBKDF2, используемого для развертки ключа из пароля.

\--without-caption
:   Опция запрещает печать заголовка, расшифровывающего названия выводимых параметров и их значений.


# ОПЦИИ

# ДОПОЛНИТЕЛЬНАЯ ИНФОРМАЦИЯ

# ПРИМЕРЫ ШИФРОВАНИЯ ИНФОРМАЦИИ


# ПРИМЕРЫ КОНТРОЛЯ ЦЕЛОСТНОСТИ

## akrypt i file.txt -o result.streebog

Данный вызов вычисляет контрольную сумму файла file.txt с помощью установленного по умолчанию
алгоритма "Стребог256" и помещает результат вычислений в файл result.streebog.

## akrypt i -rt "*.t??" -a omac-kuznechik -p .

Данный вызов позволяет вычислить код целостности всех файлов, удовлетворяющих шаблону "*.t??"
(файлы, имеющие расширение из трех символов, начинающееся с символа t) в текущем каталоге (на это указывает символ "."),
а также во всех доступных вложенных каталогах. Для вычисления кода целостности используется
алгоритм выработки имитовставки ГОСТ Р 34.13-2015 в основе которого лежит блочный шифр "Кузнечик".
Для имитозащиты файлов используется ключ, вырабатываемый из пароля, который должен быть введен пользователем.

## akrypt i -c result.streebog

Данный вызов позволяет проверить контрольные суммы, указанные в файле result.streebog.
При проверке используется установленный по-умолчанию алгоритм "Стрибог256".

## akrypt i -c result.txt -a hmac-streebog256 --password aQ13jzUl

Данный вызов позволяет проверить значения имитовставок, указанных в файле result.txt
При проверке используется алгоритм hmac-streebog256, регламентированный Р 50.1.113-2016. Ключ имитозащиты
вырабатывается из пароля, указанного пользователем в командной строке в явном виде.


# СРАВНЕНИЕ С УТИЛИТАМИ С АНАЛОГИЧНОЙ ФУНКЦИОНАЛЬНОСТЬЮ

## Контроль целостности файлов

Известны две общедоступные утилиты, позволяющие вычислять контрольные суммы с помощью
отечественных алгоритмов хеширования. Этими утилитами являются

 - gost12sum ( https://github.com/gost-engine/engine ),

 - rhash ( https://github.com/rhash/RHash ).

Следующая последовательность команд позволяет продемонстрировать эквивалентность
работы всех трех утилит для алгоритма хеширования Стрибог-256.

    echo -n hello > test.file
    gost12sum test.file
    3fb0700a41ce6e41413ba764f98bf2135ba6ded516bea2fae8429cc5bdd46d6d test.file

    rhash -G test.file
    3fb0700a41ce6e41413ba764f98bf2135ba6ded516bea2fae8429cc5bdd46d6d  test.file

    akrypt i test.file
    3FB0700A41CE6E41413BA764F98BF2135BA6DED516BEA2FAE8429CC5BDD46D6D test.file

Аналогично, для алгоритма хеширования Стрибог512,
запуск следующих команд также позволит получить одинаковое значение хэш-кода размером 512 бит.

    gost12sum -l test.file
    rhash --gost12-512 test.file
    akrypt i -a streebog512 test.file


# СТАНДАРТЫ

Национальные стандарты Российской Федерации

 - ГОСТ Р 34.10-2012,

 - ГОСТ Р 34.11-2012,

 - ГОСТ Р 34.12-2015,

 - ГОСТ Р 34.13-2015.

Рекомендации по стандартизации Росстандарта России

 - Р 50.1.111-2016,

 - Р 50.1.113-2016


# ИНФОРМАЦИЯ О ПРОЕКТЕ
Сайт проекта http://libakrypt.org

Исходные коды проекта: https://github.com/axelkenzo/libakrypt-0.x

# АВТОРЫ
Axel Kenzo & The Company Of Belles Lettres (с) 2014 - 2019

