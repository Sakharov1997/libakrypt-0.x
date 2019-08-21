/* ----------------------------------------------------------------------------------------------- */
/*  Файл ak_asn_codec.h                                                                           */
/*  - содержит перечень стандартных типов ASN.1;                                                   */
/*  - содержит перечень описаний функций кодирования и декодирования стандартных типов ASN.1;      */
/* ----------------------------------------------------------------------------------------------- */

#ifndef __AK_ASN_H__
#define __AK_ASN_H__

#include <libakrypt.h>

/*! \brief флаги, определяющие класс данных ASN.1. */
#define UNIVERSAL           0x00u
#define APPLICATION         0x40u
#define CONTEXT_SPECIFIC    0x80u
#define PRIVATE             0xC0u

/*! \brief флаг, определяющий структуру блока данных ASN.1. */
#define PRIMITIVE           0x00u
#define CONSTRUCTED         0x20u

/*! \brief номера стандартных тегов ASN.1. */
#define TEOC                0x00u
#define TBOOLEAN            0x01u
#define TINTEGER            0x02u
#define TBIT_STRING         0x03u
#define TOCTET_STRING       0x04u
#define TNULL               0x05u
#define TOBJECT_IDENTIFIER  0x06u
#define TOBJECT_DESCRIPTOR  0x07u
#define TEXTERNAL           0x08u
#define TREAL               0x09u
#define TENUMERATED         0x0Au
#define TUTF8_STRING        0x0Cu
#define TSEQUENCE           0x10u
#define TSET                0x11u
#define TNUMERIC_STRING     0x12u
#define TPRINTABLE_STRING   0x13u
#define TT61_STRING         0x14u
#define TVIDEOTEX_STRING    0x15u
#define TIA5_STRING         0x16u
#define TUTCTIME            0x17u
#define TGENERALIZED_TIME   0x18u
#define TGRAPHIC_STRING     0x19u
#define TVISIBLE_STRING     0x1Au
#define TGENERAL_STRING     0x1Bu
#define TUNIVERSAL_STRING   0x1Cu
#define TCHARACTER_STRING   0x1Du
#define TBMP_STRING         0x1Eu

/*! \brief Биты, определяющие класс данных */
#define DATA_CLASS(x)     ((x) & 0xC0)
/*! \brief Бит, определяющий структуру данных */
#define DATA_STRUCTURE(x) ((x) & 0x20)
/*! \brief Биты, определяющие номер тега */
#define TAG_NUMBER(x)     ((x) & 0x1F)

/*! \brief Длина тега (текущая реализация поддерживает кодирование
 *         и декодирование тегов, представленных одним байтом) */
#define TAG_LEN 1

/*! \brief Струкртура, хранящая целочисленые значения в соответствии с ASN.1. */
struct s_asn_int_type {
    /*! \brief массив, содержащий значение в формате big-endian. */
    ak_byte *mp_value;
    /*! \brief размер массива с данными. */
    ak_uint32 m_val_len;
    /*! \brief флаг, определяющий знак числа. */
    bool_t m_positive;
};

/*! \brief Струкртура, хранящая массив байтов в соответствии с ASN.1. */
struct s_asn_oct_str_type {
    /*! \brief массив, содержащий значение. */
    ak_byte *mp_value;
    /*! \brief размер массива с данными. */
    ak_uint32 m_val_len;
};

/*! \brief Струкртура, хранящая "битовую строку" в соответствии с ASN.1. */
struct s_asn_bit_str_type {
    /*! \brief массив, содержащий значение. */
    ak_byte *mp_value;
    /*! \brief размер массива с данными. */
    ak_uint32 m_val_len;
    /*! \brief кол-во неиспользуемых битов в последнем байте
               (возмжные значения от 0 до 7 включительно). */
    ak_uint8 m_unused;
};

typedef ak_byte tag;

/*! \brief Псевдонимы базовых типов ASN.1 */
typedef bool_t boolean;
typedef ak_uint32 integer;
typedef ak_byte *utf8_string;
typedef char *visible_string;
typedef char *generalized_time;
typedef char *ia5_string;
typedef char *printable_string;
typedef char *numeric_string;
typedef char *utc_time;
typedef char *object_identifier;
typedef struct s_asn_bit_str_type bit_string;
typedef struct s_asn_oct_str_type octet_string;

/* Создаем псевдонимы типов, чтобы можно было сослаться друг на друга при описании стурктур */
typedef struct s_constructed_data s_constructed_data_t;
typedef struct s_asn_tlv s_asn_tlv_t;

/*! \brief Струкртура, хранящая данные, из которых состоит составной TLV. */
struct s_constructed_data
{
  /*! \brief массив данных. */
  s_asn_tlv_t* mp_arr_of_data;
  /*! \brief количество объектов в массиве. */
  ak_uint8 m_curr_size;
  /*! \brief размер массива. */
  ak_uint8 m_alloc_size;
};

/*! \brief Объединение, определяющее способ представления данных (примитивное или составное). */
union u_data_representation
{
  /*! \brief указатель на примитивные данные. (Закодированые по правилам ASN.1 данные) */
  ak_byte* mp_primitive_data;
  /*! \brief указатель на составные данные. */
  s_constructed_data_t* mp_constructed_data;
};

/*! \brief Струкртура, хранящая массив указателей на данные, из которых состоит составной TLV. */
struct s_asn_tlv
{
  /*! \brief тег, идентифицирующий данные. */
  tag m_tag;
  /*! \brief длинна данных. */
  ak_uint32 m_data_len;
  /*! \brief данные. */
  union u_data_representation m_data;

  /*! \brief количество байтов, необходимое для кодирования длинные данных. */
  ak_uint8 m_len_byte_cnt;
  /*! \brief флаг, определяющий, должен ли объект освобождать память. */
  bool_t m_free_mem;
  /*! \brief название данных. */
  char* p_name;
};

typedef struct s_asn_tlv* ak_asn_tlv;

/* ---------------------- Функции управления структурой s_asn_tlv (деревом) ---------------------- */

/*! \brief Преобразует ASN.1 последовательность в структуру s_asn_tlv (дерево). */
int ak_asn_build_data(ak_asn_tlv p_tlv, ak_byte** pp_asn_data, ak_uint32* p_size);

/*! \brief Преобразует структуру s_asn_tlv (дерево) в ASN.1 последовательность. */
int ak_asn_parse_data(ak_pointer p_asn_data, size_t size, ak_asn_tlv p_tlv);

/*! \brief Кодирует примитивные ASN.1 данные базовых типов. */
int ak_asn_encode_universal_data(ak_uint8 tag_number, ak_pointer p_data, char* p_name, ak_asn_tlv p_tlv);

/*! \brief Декодирует примитивные ASN.1 данные базовых типов. */
int ak_asn_decode_universal_data(ak_asn_tlv p_tlv, ak_pointer* pp_data, ak_uint32* p_size);

/*! \brief Создает контекст составных данных. */
int ak_asn_construct_data_ctx_create(ak_asn_tlv p_tlv, tag constructed_data_tag, char* p_data_name);

/*! \brief Создает контекст примитивных данных. */
int ak_asn_primitive_data_ctx_create(ak_asn_tlv p_tlv, tag data_tag, ak_uint32 data_len, ak_pointer p_data, char* p_data_name);

/*! \brief Получает размер памяти, необходимый для кодирования ASN.1 данных. */
int ak_asn_get_size(ak_asn_tlv p_tlv, ak_uint32* p_size);

/*! \brief Пересчитывает длинны составных данных. (Используется для обновления информации о длинах после изменений.) */
int ak_asn_update_size(ak_asn_tlv p_root_tlv);

/*! \brief Отображет посредством псевдографики структуру ASN.1 данных в виде дерева. */
void new_ak_asn_print_tree(ak_asn_tlv p_tree);

/*! \brief Выводит шестнадцатеричные данных. */
void ak_asn_print_hex_data(ak_byte* p_data, ak_uint32 size);

/*! \brief Добавляет вложенный элемент в составной объект s_asn_tlv. */
int ak_asn_add_nested_elems(ak_asn_tlv p_tlv_parent, s_asn_tlv_t p_tlv_children[], ak_uint8 count);

/*! \brief Удаляет вложенный элемент из составного объекта s_asn_tlv. */
int ak_asn_delete_nested_elem(ak_asn_tlv p_tlv_parent, ak_uint32 index);

/*! \brief Очищает память, выделенную под хранение структуры дерева и внутренних данных. */
void ak_asn_free_tree(ak_asn_tlv p_tlv_root);

/* ---------------------- Функции декодирования ASN.1 данных ---------------------- */

/*! \brief Декодирует тег данных из ASN.1 последовательности. */
int new_asn_get_tag(ak_byte** pp_data, tag *p_tag);

/*! \brief Декодирует длину данных из ASN.1 последовательности. */
int new_asn_get_len(ak_byte** pp_data, size_t *p_len);

/*! \brief Декодирует Integer из ASN.1 последовательности. */
int new_asn_get_int(ak_byte *p_buff, ak_uint32 len, integer *p_val);

/*! \brief Декодирует UTF-8 string из ASN.1 последовательности. */
int new_asn_get_utf8string(ak_byte *p_buff, size_t len, utf8_string *p_str);

/*! \brief Декодирует Octet string из ASN.1 последовательности. */
int new_asn_get_octetstr(ak_byte *p_buff, size_t len, octet_string *p_dst);

/*! \brief Декодирует Visible string из ASN.1 последовательности. */
int new_asn_get_vsblstr(ak_byte *p_buff, size_t len, visible_string *p_str);

/*! \brief Декодирует Object identifier из ASN.1 последовательности. */
int new_asn_get_objid(ak_byte *p_buff, size_t len, object_identifier *p_objid);

/*! \brief Декодирует Bit string из ASN.1 последовательности. */
int new_asn_get_bitstr(ak_byte *p_buff, size_t len, bit_string *p_dst);

/*! \brief Декодирует Boolean из ASN.1 последовательности. */
int new_asn_get_bool(ak_byte *p_buff, size_t len, boolean *p_value);

/*! \brief Декодирует Generalized time из ASN.1 последовательности. */
int new_asn_get_generalized_time(ak_byte *p_buff, size_t len, generalized_time *p_time);

/*! \brief Декодирует Printable string из ASN.1 последовательности. */
int new_asn_get_printable_string(ak_byte* p_buff, ak_uint32 size, printable_string* p_str);

/*! \brief Декодирует IA5 string из ASN.1 последовательности. */
int new_asn_get_ia5string(ak_byte* p_buff, ak_uint32 size, ia5_string* p_str);

/*! \brief Декодирует Numeric string из ASN.1 последовательности. */
int new_asn_get_numeric_string(ak_byte* p_buff, ak_uint32 size, numeric_string* p_str);

/*! \brief Декодирует UTC time из ASN.1 последовательности. */
int new_asn_get_utc_time(ak_byte* p_buff, ak_uint32 len, utc_time* p_time);

/* ---------------------- Функции кодирования ASN.1 данных ---------------------- */

/*! \brief Кодирует тег данных в ASN.1 последовательность. */
int new_asn_put_tag(tag tag, ak_byte **pp_buff);

/*! \brief Кодирует длину данных в ASN.1 последовательность. */
int new_asn_put_len(size_t len, ak_uint32 len_byte_cnt, ak_byte **pp_buff);

/*! \brief Кодирует Integer в ASN.1 последовательность. */
int new_asn_put_int(integer val, ak_byte** pp_buff, ak_uint32* p_size);

/*! \brief Кодирует UTF-8 string в ASN.1 последовательность. */
int new_asn_put_utf8string(utf8_string str, ak_byte** pp_buff, ak_uint32* p_size);

/*! \brief Кодирует Octet string в ASN.1 последовательность. */
int new_asn_put_octetstr(octet_string src, ak_byte** pp_buff, ak_uint32* p_size);

/*! \brief Кодирует Visible string в ASN.1 последовательность. */
int new_asn_put_vsblstr(visible_string str, ak_byte** pp_buff, ak_uint32* p_size);

/*! \brief Кодирует Object identifier в ASN.1 последовательность. */
int new_asn_put_objid(object_identifier obj_id, ak_byte** pp_buff, ak_uint32* p_size);

/*! \brief Кодирует Bit string в ASN.1 последовательность. */
int new_asn_put_bitstr(bit_string src, ak_byte** pp_buff, ak_uint32* p_size);

/*! \brief Кодирует Boolean в ASN.1 последовательность. */
int new_asn_put_bool(boolean val, ak_byte** pp_buff, ak_uint32* p_size);

/*! \brief Кодирует Generalized time в ASN.1 последовательность. */
int new_asn_put_generalized_time(generalized_time time, ak_byte** pp_buff, ak_uint32* p_size);

/*! \brief Кодирует IA5 string в ASN.1 последовательность. */
int new_asn_put_ia5string(ia5_string str, ak_byte** pp_buff, ak_uint32* p_size);

/*! \brief Кодирует Printable string в ASN.1 последовательность. */
int new_asn_put_printable_string(printable_string str, ak_byte** pp_buff, ak_uint32* p_size);

/*! \brief Кодирует Numeric string в ASN.1 последовательность. */
int new_asn_put_numeric_string(numeric_string str, ak_byte** pp_buff, ak_uint32* p_size);

/*! \brief Кодирует UTC time в ASN.1 последовательность. */
int new_asn_put_utc_time(utc_time time, ak_byte** pp_buff, ak_uint32* p_size);

/* ---------------------- Tools ---------------------- */

/*! \brief Определяет необходимое количество памяти для хранения длины данных. */
ak_uint8 new_asn_get_len_byte_cnt(size_t len);

/*! \brief Определяет необходимое количество памяти для хранения данных типа Object identifier. */
ak_uint8 new_asn_get_oid_byte_cnt(object_identifier oid);

/*! \brief Определяет необходимое количество памяти для хранения данных типа Generalized time. */
ak_uint8 new_asn_get_gentime_byte_cnt(generalized_time time);

/*! \brief Получает символьное представление идентификатора объекта (Object identifier). */
int ak_asn_get_oid_desc(object_identifier oid, char** pp_desc);

/*! \brief Заполняет структуру bit_string данными из строки. */
int ak_bitstr_set_str(bit_string* p_bit_str, char* str);

/*! \brief Заполняет структуру bit_string данными из значение типа ak_uint64. */
int ak_bitstr_set_ui(bit_string* p_bit_str, ak_uint64 val64, ak_uint8 used_bits);

/*! \brief Заполняет структуру bit_string данными из массива. */
int ak_bitstr_set_arr(bit_string* p_bit_str, ak_byte* p_data, ak_uint32 size, ak_uint8 unused_bits);

/*! \brief Представляет данные из структуры bit_string в виде строки. */
int ak_bitstr_get_str(bit_string* p_bit_str, char** pp_str);

/*! \brief Записывает данные из структуры bit_string в переменную типа ak_uint64. */
int ak_bitstr_get_ui(bit_string* p_bit_str, ak_uint64* p_val64, ak_uint8* p_used_bits);

/*! \brief Записывает данные из структуры bit_string в массива. */
int ak_bitstr_get_arr(bit_string* p_bit_str, ak_byte** pp_data, ak_uint32* p_size, ak_uint8* p_unused_bits);

/*! \brief Проверяет строку на соответствие формату Printable string. */
bool_t check_prntbl_str(printable_string str, ak_uint32 len);

/*! \brief Освобождение памяти. */
//void asn_free_int(integer *p_val);
//
//void asn_free_utf8string(utf8_string *p_val);
//
//void asn_free_octetstr(octet_string *p_val);
//
//void asn_free_vsblstr(visible_string *p_val);
//
//void asn_free_objid(object_identifier *p_val);
//
//void asn_free_bitstr(bit_string *p_val);
//
//void asn_free_generalized_time(generalized_time *p_val);

#endif /* __AK_ASN_H__ */
