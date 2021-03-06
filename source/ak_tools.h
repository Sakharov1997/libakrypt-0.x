/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_tools.h                                                                                */
/*  - содержит описания служебных функций и переменных, не экспортируемых за пределы библиотеки    */
/* ----------------------------------------------------------------------------------------------- */
 #ifndef    __AK_TOOLS_H__
 #define    __AK_TOOLS_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_WINDOWS_H
 #include <windows.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура данных для хранения дескриптора и параметров файла. */
 typedef struct file {
#ifdef LIBAKRYPT_HAVE_WINDOWS_H
 /*! \brief Дескриптор файла для операционной системы Windows. */
  HANDLE hFile;
#else
 /*! \brief Дескриптор файла. */
  int fd;
#endif
 /*! \brief Размер файла. */
  ak_int64 size;
 /*! \brief Размер блока для оптимального чтения с жесткого диска. */
  ak_int64 blksize;
 } *ak_file;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция открывает заданный файл на чтение. */
 int ak_file_open_to_read( ak_file , const char * ); 
/*! \brief Функция создает файл с правами на запись. */
 int ak_file_create_to_write( ak_file , const char * );
/*! \brief Функция закрывает файл с заданным дескриптором. */
 int ak_file_close( ak_file );
/*! \brief Функция считывает заданное количество байт из файла. */
 ssize_t ak_file_read( ak_file , ak_pointer , size_t );
/*! \brief Функция записывает заданное количество байт в файл. */
 ssize_t ak_file_write( ak_file , ak_const_pointer , size_t );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция устанавливает значение опции с заданным именем. */
 int ak_libakrypt_set_option( const char *name, const ak_int64 value );
/*! \brief Функция возвращает значение опции с заданным именем. */
 ak_int64 ak_libakrypt_get_option( const char *name );
/*! \brief Вывод в логгер текущих значений опций библиотеки. */
 void ak_libakrypt_log_options( void );

/* ----------------------------------------------------------------------------------------------- */
#ifndef LIBAKRYPT_CONST_CRYPTO_PARAMS
/*! \brief Функция создает полное имя файла в служебном каталоге библиотеки. */
 int ak_libakrypt_create_filename( char * , const size_t , char * , const int );
/*! \brief Функция считывает настройки (параметры) библиотеки из файла libakrypt.conf */
 bool_t ak_libakrypt_load_options( void );
#endif

#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_libakrypt.h  */
/* ----------------------------------------------------------------------------------------------- */
