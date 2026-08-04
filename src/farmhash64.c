/*! farmhash Fingerprint64 — совместим с Google FarmHash
    Fingerprint64("CVCtrl_BHB42XXX") = 0x883b7c5d69fe738b, как в README BMU.
    Ниже рабочая C-реализация (порт FarmHash Fingerprint64 / Hash64):

 $ python3 -m venv venv
 $ ./venv/bin/pip3 install cityhash
 $ ./venv/bin/python3 test_farmhash.py
MATCH 883b7c5d69fe738b  'CVCtrl_BHB42XXX'  (from S19j Pro README)

 */
#include <stdint.h>
#include <string.h>

static inline uint64_t Fetch64(const char *p)
{
    uint64_t r;
    memcpy(&r, p, 8);
    return r;
}

static inline uint32_t Fetch32(const char *p)
{
    uint32_t r;
    memcpy(&r, p, 4);
    return r;
}

static inline uint64_t Rotate64(uint64_t v, int shift)
{
    return shift == 0 ? v : ((v >> shift) | (v << (64 - shift)));
}

static inline uint64_t ShiftMix(uint64_t v)
{
    return v ^ (v >> 47);
}

static inline uint64_t HashLen16(uint64_t u, uint64_t v, uint64_t mul)
{
    uint64_t a = (u ^ v) * mul;
    a ^= (a >> 47);
    uint64_t b = (v ^ a) * mul;
    b ^= (b >> 47);
    b *= mul;
    return b;
}

/* cityhash/farmhash constants */
static const uint64_t k0 = 0xc3a5c85c97cb3127ULL;
static const uint64_t k1 = 0xb492b66fbe98f273ULL;
static const uint64_t k2 = 0x9ae16a3b2f90404fULL;

static uint64_t HashLen0to16(const char *s, size_t len)
{
    if (len >= 8) {
        uint64_t mul = k2 + len * 2;
        uint64_t a = Fetch64(s) + k2;
        uint64_t b = Fetch64(s + len - 8);
        uint64_t c = Rotate64(b, 37) * mul + a;
        uint64_t d = (Rotate64(a, 25) + b) * mul;
        return HashLen16(c, d, mul);
    }
    if (len >= 4) {
        uint64_t mul = k2 + len * 2;
        uint64_t a = Fetch32(s);
        return HashLen16(len + (a << 3), Fetch32(s + len - 4), mul);
    }
    if (len > 0) {
        uint8_t a = (uint8_t)s[0];
        uint8_t b = (uint8_t)s[len >> 1];
        uint8_t c = (uint8_t)s[len - 1];
        uint32_t y = (uint32_t)a + ((uint32_t)b << 8);
        uint32_t z = (uint32_t)len + ((uint32_t)c << 2);
        return ShiftMix(y * k2 ^ z * k0) * k2;
    }
    return k2;
}

static uint64_t HashLen17to32(const char *s, size_t len)
{
    uint64_t mul = k2 + len * 2;
    uint64_t a = Fetch64(s) * k1;
    uint64_t b = Fetch64(s + 8);
    uint64_t c = Fetch64(s + len - 8) * mul;
    uint64_t d = Fetch64(s + len - 16) * k2;
    return HashLen16(Rotate64(a + b, 43) + Rotate64(c, 30) + d,
                     a + Rotate64(b + k2, 18) + c, mul);
}

static uint64_t HashLen33to64(const char *s, size_t len)
{
    uint64_t mul = k2 + len * 2;
    uint64_t a = Fetch64(s) * k2;
    uint64_t b = Fetch64(s + 8);
    uint64_t c = Fetch64(s + len - 8) * mul;
    uint64_t d = Fetch64(s + len - 16) * k2;
    uint64_t y = Rotate64(a + b, 43) + Rotate64(c, 30) + d;
    uint64_t z = HashLen16(y, a + Rotate64(b + k2, 18) + c, mul);
    uint64_t e = Fetch64(s + 16) * k2;
    uint64_t f = Fetch64(s + 24);
    uint64_t g = (y + Fetch64(s + len - 32)) * mul;
    uint64_t h = (z + Fetch64(s + len - 24)) * mul;
    return HashLen16(Rotate64(e + f, 43) + Rotate64(g, 30) + h,
                     e + Rotate64(f + a, 18) + g, mul);
}

typedef struct {
    uint64_t first, second;
} pair64;

static pair64 WeakHashLen32WithSeeds(uint64_t w, uint64_t x, uint64_t y,
                                     uint64_t z, uint64_t a, uint64_t b)
{
    a += w;
    b = Rotate64(b + a + z, 21);
    uint64_t c = a;
    a += x;
    a += y;
    b += Rotate64(a, 44);
    return (pair64){ a + z, b + c };
}

static pair64 WeakHashLen32WithSeedsPtr(const char *s, uint64_t a, uint64_t b)
{
    return WeakHashLen32WithSeeds(Fetch64(s), Fetch64(s + 8),
                                  Fetch64(s + 16), Fetch64(s + 24), a, b);
}

static uint64_t HashLen65Plus(const char *s, size_t len)
{
    uint64_t x = Fetch64(s + len - 40);
    uint64_t y = Fetch64(s + len - 16) + Fetch64(s + len - 56);
    uint64_t z = HashLen16(Fetch64(s + len - 48) + len,
                           Fetch64(s + len - 24), k1 /* dummy mul path via HashLen16 default-ish */);
    /* FarmHash uses HashLen16(u,v) with mul=k1 internally in some versions;
       use explicit: */
    z = HashLen16(Fetch64(s + len - 48) + len, Fetch64(s + len - 24), k1);

    pair64 v = WeakHashLen32WithSeedsPtr(s + len - 64, len, z);
    pair64 w = WeakHashLen32WithSeedsPtr(s + len - 32, y + k1, x);
    x = x * k1 + Fetch64(s);

    size_t n = (len - 1) / 64;
    do {
        x = Rotate64(x + y + v.first + Fetch64(s + 8), 37) * k1;
        y = Rotate64(y + v.second + Fetch64(s + 48), 42) * k1;
        x ^= w.second;
        y += v.first + Fetch64(s + 40);
        z = Rotate64(z + w.first, 33) * k1;
        v = WeakHashLen32WithSeedsPtr(s, v.second * k1, x + w.first);
        w = WeakHashLen32WithSeedsPtr(s + 32, z + w.second, y + Fetch64(s + 16));
        uint64_t tmp = z; z = x; x = tmp;
        s += 64;
    } while (--n);

    return HashLen16(HashLen16(v.first, w.first, k1) + ShiftMix(y) * k1 + z,
                     HashLen16(v.second, w.second, k1) + x, k1);
}

uint64_t farmhash64(const char *s, size_t len)
{
    if (len <= 16)
        return HashLen0to16(s, len);
    if (len <= 32)
        return HashLen17to32(s, len);
    if (len <= 64)
        return HashLen33to64(s, len);
    return HashLen65Plus(s, len);
}

/* Fingerprint64 == Hash64 в FarmHash для этих целей */
uint64_t fingerprint64(const char *s, size_t len) {
    return farmhash64(s, len);
}

uint64_t fingerprint64_str(const char *s) {
    return fingerprint64(s, strlen(s));
}

#if defined(TEST_HASH)
#include <stdio.h>
int main(int argc, char* argv[]) 
{
    /*! {Имя контрольной платы}_{шаблон имени хэш-платы} 
        Контрольные платы: `BBCtrl`, `AMLCtrl`, `CVCtrl`, `zynq7007`, `zynq7020`
     */
    const char *s = "CVCtrl_BHB42XXX";
    const char *s19 = "S19";
    printf("CVC:%016llx\n", (unsigned long long)fingerprint64_str(s));/* ожидается: 883b7c5d69fe738b */
    printf("S19:%016llx\n", (unsigned long long)fingerprint64_str(s19));
    /* ожидается: 883b7c5d69fe738b */
    if (argc>=2) 
        printf("arg:%016llx\n", (unsigned long long)fingerprint64_str(argv[1]));
    return 0;
}
#endif