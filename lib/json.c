/* SPDX-License-Identifier: MIT */
/* Minimal JSON parser and emitter for Mazu.
 *
 * Parser: recursive descent, arena-allocated.  No heap.  Floats stored as
 * fixed-point (scaled by 1e6) to avoid kernel FP.  Depth bounded.
 *
 * Emitter: low-level append-to-byte_buf primitives.
 */

#include "json.h"

#include <mazu/string.h>

/* Parser internals */

struct json_parser {
    struct str input;
    sz pos;
    struct arena *arena;
    i32 depth;
};

static inline bool jp_eof(struct json_parser *p)
{
    return p->pos >= p->input.len;
}

static inline char jp_peek(struct json_parser *p)
{
    return p->input.dat[p->pos];
}

static inline char jp_advance(struct json_parser *p)
{
    return p->input.dat[p->pos++];
}

static void jp_skip_ws(struct json_parser *p)
{
    while (!jp_eof(p)) {
        char c = jp_peek(p);
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
            p->pos++;
        else
            break;
    }
}

static struct json_result jp_error(struct json_parser *p, u16 code)
{
    return (struct json_result) {
        .is_error = true,
        .error_code = code,
        .error_offset = p->pos,
    };
}

static struct json_result jp_ok(struct json_value val)
{
    return (struct json_result) {
        .value = val,
    };
}

/* Forward declaration for recursive parsing. */
static struct json_result jp_parse_value(struct json_parser *p);

static struct json_result jp_parse_string(struct json_parser *p)
{
    if (jp_eof(p) || jp_peek(p) != '"')
        return jp_error(p, JSON_ERR_UNEXPECTED_TOKEN);

    jp_advance(p); /* consume opening quote */

    sz start = p->pos;
    bool has_escape = false;

    while (!jp_eof(p)) {
        char c = jp_advance(p);
        if (c == '"') {
            struct json_value val;
            val.type = JSON_STRING;
            if (!has_escape) {
                val.v.string =
                    str_new(p->input.dat + start, p->pos - 1 - start);
            } else {
                /* Re-scan and unescape into arena. */
                sz raw_len = p->pos - 1 - start;
                char *buf = arena_alloc(p->arena, raw_len);
                sz out = 0;
                for (sz i = start; i < p->pos - 1; i++) {
                    char ch = p->input.dat[i];
                    if (ch == '\\' && i + 1 < p->pos - 1) {
                        i++;
                        char esc = p->input.dat[i];
                        switch (esc) {
                        case '"':
                            buf[out++] = '"';
                            break;
                        case '\\':
                            buf[out++] = '\\';
                            break;
                        case '/':
                            buf[out++] = '/';
                            break;
                        case 'n':
                            buf[out++] = '\n';
                            break;
                        case 'r':
                            buf[out++] = '\r';
                            break;
                        case 't':
                            buf[out++] = '\t';
                            break;
                        case 'b':
                            buf[out++] = '\b';
                            break;
                        case 'f':
                            buf[out++] = '\f';
                            break;
                        default:
                            buf[out++] = '\\';
                            buf[out++] = esc;
                            break;
                        }
                    } else {
                        buf[out++] = ch;
                    }
                }
                val.v.string = str_new(buf, out);
            }
            return jp_ok(val);
        }
        if (c == '\\') {
            has_escape = true;
            if (jp_eof(p))
                break;
            jp_advance(p); /* skip escaped char */
        }
    }
    return jp_error(p, JSON_ERR_UNTERMINATED_STRING);
}

static struct json_result jp_parse_number(struct json_parser *p)
{
    sz start = p->pos;
    bool negative = false;
    bool is_float = false;

    if (!jp_eof(p) && jp_peek(p) == '-') {
        negative = true;
        jp_advance(p);
    }

    /* Integer part. */
    u64 int_part = 0;
    while (!jp_eof(p) && jp_peek(p) >= '0' && jp_peek(p) <= '9') {
        u64 d = jp_peek(p) - '0';
        u64 limit = negative ? 9223372036854775808ULL : 9223372036854775807ULL;
        if (int_part > (limit - d) / 10)
            return jp_error(p, JSON_ERR_OVERFLOW);
        int_part = int_part * 10 + d;
        jp_advance(p);
    }

    /* Fractional part. */
    i64 frac_scaled = 0;
    if (!jp_eof(p) && jp_peek(p) == '.') {
        is_float = true;
        jp_advance(p);
        i64 scale = 100000; /* 1e5: multiply each digit and add */
        while (!jp_eof(p) && jp_peek(p) >= '0' && jp_peek(p) <= '9') {
            if (scale > 0) {
                frac_scaled += (jp_peek(p) - '0') * scale;
                scale /= 10;
            }
            jp_advance(p);
        }
    }

    /* Exponent part: consumed for well-formedness but not applied to
     * the value.  Scientific notation (e.g. 1.2e3) is parsed as 1.2.
     * Current callers only need bounded fixed-precision decimals;
     * if an exponent-aware consumer appears later, this is the place
     * to fold the exponent into int_part/frac_scaled.
     */
    if (!jp_eof(p) && (jp_peek(p) == 'e' || jp_peek(p) == 'E')) {
        is_float = true;
        jp_advance(p);
        if (!jp_eof(p) && (jp_peek(p) == '+' || jp_peek(p) == '-'))
            jp_advance(p);
        while (!jp_eof(p) && jp_peek(p) >= '0' && jp_peek(p) <= '9')
            jp_advance(p);
    }

    if (p->pos == start || (p->pos == start + 1 && negative))
        return jp_error(p, JSON_ERR_UNEXPECTED_TOKEN);

    struct json_value val;
    if (is_float) {
        val.type = JSON_FLOAT;
        /* Guard against overflow: int_part * 1e6 + frac_scaled must fit
         * in i64.  frac_scaled is at most 999999.
         */
        if (int_part > ((u64) I64_MAX - 999999) / 1000000)
            return jp_error(p, JSON_ERR_OVERFLOW);
        val.v.fixed_point = (i64) int_part * 1000000 + frac_scaled;
        if (negative)
            val.v.fixed_point = -val.v.fixed_point;
    } else {
        val.type = JSON_INT;
        /* Negate in unsigned to avoid UB at I64_MIN boundary. */
        val.v.integer = negative ? (i64) (0 - int_part) : (i64) int_part;
    }
    return jp_ok(val);
}

static bool jp_match(struct json_parser *p, const char *s, sz len)
{
    if (p->pos + len > p->input.len)
        return false;
    for (sz i = 0; i < len; i++) {
        if (p->input.dat[p->pos + i] != s[i])
            return false;
    }
    p->pos += len;
    return true;
}

#define JSON_CONTAINER_MAX 64

/* Bound the per-container element count so that 'count * sizeof(element)'
 * is provably representable in 'sz' and cannot wrap. Callers further down
 * pass 'count' to arena_alloc_array() and memcpy(); without this compile
 * time bound the multiplication would need a runtime overflow guard.
 */
static_assert(JSON_CONTAINER_MAX <= SZ_MAX / sizeof(struct json_value),
              "JSON_CONTAINER_MAX too large for json_value allocation");
static_assert(JSON_CONTAINER_MAX <= SZ_MAX / sizeof(struct json_kv),
              "JSON_CONTAINER_MAX too large for json_kv allocation");

static struct json_result jp_parse_array(struct json_parser *p)
{
    if (p->depth >= JSON_MAX_DEPTH)
        return jp_error(p, JSON_ERR_DEPTH_EXCEEDED);
    p->depth++;

    jp_advance(p); /* consume '[' */
    jp_skip_ws(p);

    struct json_value tmp_items[JSON_CONTAINER_MAX];
    sz count = 0;

    if (!jp_eof(p) && jp_peek(p) != ']') {
        for (;;) {
            if (count >= JSON_CONTAINER_MAX)
                return jp_error(p, JSON_ERR_OVERFLOW);
            struct json_result elem = jp_parse_value(p);
            if (elem.is_error) {
                p->depth--;
                return elem;
            }
            tmp_items[count++] = elem.value;
            jp_skip_ws(p);
            if (jp_eof(p)) {
                p->depth--;
                return jp_error(p, JSON_ERR_UNEXPECTED_TOKEN);
            }
            if (jp_peek(p) == ',') {
                jp_advance(p);
                jp_skip_ws(p);
            } else {
                break;
            }
        }
    }

    if (jp_eof(p) || jp_peek(p) != ']') {
        p->depth--;
        return jp_error(p, JSON_ERR_UNEXPECTED_TOKEN);
    }
    jp_advance(p); /* consume ']' */
    p->depth--;

    struct json_value val;
    val.type = JSON_ARRAY;
    val.v.array.count = count;
    if (count > 0) {
        val.v.array.items =
            arena_alloc_array(p->arena, count, sizeof(struct json_value));
        memcpy(val.v.array.items, tmp_items, count * sizeof(struct json_value));
    } else {
        val.v.array.items = NULL;
    }
    return jp_ok(val);
}

static struct json_result jp_parse_object(struct json_parser *p)
{
    if (p->depth >= JSON_MAX_DEPTH)
        return jp_error(p, JSON_ERR_DEPTH_EXCEEDED);
    p->depth++;

    jp_advance(p); /* consume '{' */
    jp_skip_ws(p);

    struct json_kv tmp_pairs[JSON_CONTAINER_MAX];
    sz count = 0;

    if (!jp_eof(p) && jp_peek(p) != '}') {
        for (;;) {
            if (count >= JSON_CONTAINER_MAX)
                return jp_error(p, JSON_ERR_OVERFLOW);
            jp_skip_ws(p);
            /* Parse key (must be a string). */
            struct json_result key_res = jp_parse_string(p);
            if (key_res.is_error) {
                p->depth--;
                return key_res;
            }
            jp_skip_ws(p);
            if (jp_eof(p) || jp_peek(p) != ':') {
                p->depth--;
                return jp_error(p, JSON_ERR_UNEXPECTED_TOKEN);
            }
            jp_advance(p); /* consume ':' */
            jp_skip_ws(p);

            struct json_result val_res = jp_parse_value(p);
            if (val_res.is_error) {
                p->depth--;
                return val_res;
            }

            tmp_pairs[count].key = key_res.value.v.string;
            tmp_pairs[count].value = val_res.value;
            count++;

            jp_skip_ws(p);
            if (jp_eof(p)) {
                p->depth--;
                return jp_error(p, JSON_ERR_UNEXPECTED_TOKEN);
            }
            if (jp_peek(p) == ',') {
                jp_advance(p);
                jp_skip_ws(p);
            } else {
                break;
            }
        }
    }

    if (jp_eof(p) || jp_peek(p) != '}') {
        p->depth--;
        return jp_error(p, JSON_ERR_UNEXPECTED_TOKEN);
    }
    jp_advance(p); /* consume '}' */
    p->depth--;

    struct json_value val;
    val.type = JSON_OBJECT;
    val.v.object.count = count;
    if (count > 0) {
        val.v.object.pairs =
            arena_alloc_array(p->arena, count, sizeof(struct json_kv));
        memcpy(val.v.object.pairs, tmp_pairs, count * sizeof(struct json_kv));
    } else {
        val.v.object.pairs = NULL;
    }
    return jp_ok(val);
}

static struct json_result jp_parse_value(struct json_parser *p)
{
    jp_skip_ws(p);
    if (jp_eof(p))
        return jp_error(p, JSON_ERR_UNEXPECTED_TOKEN);

    char c = jp_peek(p);

    if (c == '"')
        return jp_parse_string(p);
    if (c == '{')
        return jp_parse_object(p);
    if (c == '[')
        return jp_parse_array(p);
    if (c == '-' || (c >= '0' && c <= '9'))
        return jp_parse_number(p);
    if (jp_match(p, "true", 4))
        return jp_ok(
            (struct json_value) {.type = JSON_BOOL, .v.boolean = true});
    if (jp_match(p, "false", 5))
        return jp_ok(
            (struct json_value) {.type = JSON_BOOL, .v.boolean = false});
    if (jp_match(p, "null", 4))
        return jp_ok((struct json_value) {.type = JSON_NULL});
    return jp_error(p, JSON_ERR_UNEXPECTED_TOKEN);
}

struct json_result json_parse(struct str input, struct arena *a)
{
    struct json_parser p = {
        .input = input,
        .pos = 0,
        .arena = a,
        .depth = 0,
    };

    struct json_result r = jp_parse_value(&p);
    if (r.is_error)
        return r;

    /* Check for trailing non-whitespace input. */
    jp_skip_ws(&p);
    if (!jp_eof(&p)) {
        r.is_error = true;
        r.error_code = JSON_ERR_TRAILING_INPUT;
        r.error_offset = p.pos;
    }
    return r;
}

/* Emitter */

static void emit_raw(struct byte_buf *buf, const char *s, sz len)
{
    byte_buf_append(buf, byte_view_new((void *) s, len));
}

static void emit_char(struct byte_buf *buf, char c)
{
    byte_buf_append(buf, byte_view_new(&c, 1));
}

void json_emit_object_start(struct byte_buf *buf)
{
    emit_char(buf, '{');
}

void json_emit_object_end(struct byte_buf *buf)
{
    emit_char(buf, '}');
}

void json_emit_array_start(struct byte_buf *buf)
{
    emit_char(buf, '[');
}

void json_emit_array_end(struct byte_buf *buf)
{
    emit_char(buf, ']');
}

void json_emit_comma(struct byte_buf *buf)
{
    emit_char(buf, ',');
}

void json_emit_string(struct byte_buf *buf, struct str val)
{
    emit_char(buf, '"');
    for (sz i = 0; i < val.len; i++) {
        char c = val.dat[i];
        switch (c) {
        case '"':
            emit_raw(buf, "\\\"", 2);
            break;
        case '\\':
            emit_raw(buf, "\\\\", 2);
            break;
        case '\n':
            emit_raw(buf, "\\n", 2);
            break;
        case '\r':
            emit_raw(buf, "\\r", 2);
            break;
        case '\t':
            emit_raw(buf, "\\t", 2);
            break;
        default:
            if ((u8) c < 0x20) {
                /* Control character: emit \u00XX. */
                char hex[6] = {'\\', 'u', '0', '0', 0, 0};
                hex[4] = "0123456789abcdef"[(c >> 4) & 0xf];
                hex[5] = "0123456789abcdef"[c & 0xf];
                emit_raw(buf, hex, 6);
            } else {
                emit_char(buf, c);
            }
            break;
        }
    }
    emit_char(buf, '"');
}

void json_emit_key(struct byte_buf *buf, struct str key)
{
    json_emit_string(buf, key);
    emit_char(buf, ':');
}

void json_emit_int(struct byte_buf *buf, i64 val)
{
    char tmp[21];
    char *end = tmp + sizeof(tmp);
    char *p = end;
    bool neg = val < 0;
    u64 abs_val = neg ? (u64) (-(val + 1)) + 1 : (u64) val;

    do {
        *(--p) = '0' + (abs_val % 10);
    } while (abs_val /= 10);

    if (neg)
        *(--p) = '-';

    emit_raw(buf, p, end - p);
}

void json_emit_bool(struct byte_buf *buf, bool val)
{
    if (val)
        emit_raw(buf, "true", 4);
    else
        emit_raw(buf, "false", 5);
}

void json_emit_null(struct byte_buf *buf)
{
    emit_raw(buf, "null", 4);
}

void json_emit_key_string(struct byte_buf *buf, struct str key, struct str val)
{
    json_emit_key(buf, key);
    json_emit_string(buf, val);
}

void json_emit_key_int(struct byte_buf *buf, struct str key, i64 val)
{
    json_emit_key(buf, key);
    json_emit_int(buf, val);
}

void json_emit_key_bool(struct byte_buf *buf, struct str key, bool val)
{
    json_emit_key(buf, key);
    json_emit_bool(buf, val);
}

struct json_value *json_object_get(struct json_value *obj, struct str key)
{
    if (!obj || obj->type != JSON_OBJECT)
        return NULL;
    for (sz i = 0; i < obj->v.object.count; i++) {
        if (str_is_equal(obj->v.object.pairs[i].key, key))
            return &obj->v.object.pairs[i].value;
    }
    return NULL;
}

/* Self-tests */

#include __INC_TEST(json)
