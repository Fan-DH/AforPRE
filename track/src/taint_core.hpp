#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <memory>
#include <cstdlib>
#include <unordered_map>
#include <vector>

namespace pre {
using Tag = uint32_t;
using Bytes = std::array<Tag, 64>;
struct VectorHash {
    size_t operator()(const std::vector<uint64_t> &v) const {
        size_t h = 1469598103934665603ULL;
        for (auto x : v) {
            h ^= x;
            h *= 1099511628211ULL;
        }
        return h;
    }
};
// Immutable, canonical provenance sets. 0 means untainted; origins are (input, byte).
class Tags {
    std::vector<std::vector<uint64_t>> sets_{{}};
    std::unordered_map<std::vector<uint64_t>, Tag, VectorHash> ids_;
    std::unordered_map<uint64_t, Tag> cache_;
    Tag intern(std::vector<uint64_t> v) {
        auto it = ids_.find(v);
        if (it != ids_.end())
            return it->second;
        if (sets_.size() >= std::numeric_limits<Tag>::max())
            std::abort();
        Tag id = sets_.size();
        sets_.push_back(v);
        ids_.emplace(std::move(v), id);
        return id;
    }

  public:
    Tag source(uint32_t input, uint32_t offset) {
        return intern({uint64_t(input) << 32 | offset});
    }
    Tag join(Tag a, Tag b) {
        if (!a || a == b)
            return b;
        if (!b)
            return a;
        if (a > b)
            std::swap(a, b);
        uint64_t key = uint64_t(a) << 32 | b;
        auto it = cache_.find(key);
        if (it != cache_.end())
            return it->second;
        std::vector<uint64_t> v;
        const auto &x = sets_.at(a);
        const auto &y = sets_.at(b);
        std::set_union(x.begin(), x.end(), y.begin(), y.end(), std::back_inserter(v));
        Tag result = intern(std::move(v));
        if (cache_.size() >= 65536)
            cache_.clear(); // bound the acceleration cache
        cache_[key] = result;
        return result;
    }
    Tag fold(const Bytes &b, size_t n) {
        Tag t = 0;
        for (size_t i = 0; i < n; ++i)
            t = join(t, b[i]);
        return t;
    }
    const std::vector<uint64_t> &get(Tag t) const {
        return sets_.at(t);
    }
    size_t size() const {
        return sets_.size();
    }
};
// Allocate shadow only on tainted writes. Never allocate when reading or clearing clean pages.
class Shadow {
    struct Page {
        std::array<Tag, 4096> data{};
        size_t count = 0;
    };
    std::unordered_map<uint64_t, std::unique_ptr<Page>> pages_;

  public:
    Tag get(uint64_t a) const {
        auto i = pages_.find(a >> 12);
        return i == pages_.end() ? 0 : i->second->data[a & 4095];
    }
    void set(uint64_t a, Tag t) {
        auto i = pages_.find(a >> 12);
        if (i == pages_.end()) {
            if (!t)
                return;
            i = pages_.emplace(a >> 12, std::unique_ptr<Page>(new Page)).first;
        }
        Page &p = *i->second;
        Tag &old = p.data[a & 4095];
        p.count += (!old && t);
        p.count -= (old && !t);
        old = t;
        if (!p.count)
            pages_.erase(i);
    }
    Bytes read(uint64_t a, size_t n) const {
        Bytes b{};
        for (size_t i = 0; i < n; ++i)
            b[i] = get(a + i);
        return b;
    }
    void write(uint64_t a, const Bytes &b, size_t n) {
        for (size_t i = 0; i < n; ++i)
            set(a + i, b[i]);
    }
    void clear(uint64_t a, uint64_t n) {
        while (n) {
            uint64_t k = std::min<uint64_t>(n, 4096 - (a & 4095));
            if (!(a & 4095) && k == 4096)
                pages_.erase(a >> 12);
            else if (pages_.count(a >> 12))
                for (uint64_t j = 0; j < k; ++j)
                    set(a + j, 0);
            a += k;
            n -= k;
        }
    }
    size_t pages() const {
        return pages_.size();
    }
};
inline Bytes extend(const Bytes &src, size_t from, size_t to, bool sign) {
    Bytes r{};
    for (size_t i = 0; i < to; ++i)
        r[i] = i < from ? src[i] : (sign && from ? src[from - 1] : 0);
    return r;
}
inline void write_register(Bytes &reg, size_t off, size_t n, const Bytes &value, bool zero_upper) {
    std::copy_n(value.begin(), n, reg.begin() + off);
    if (zero_upper)
        std::fill(reg.begin() + off + n, reg.end(), 0);
}
// Byte provenance of bit shifts: union only bytes that contribute bits to each output byte.
inline Bytes shift(Tags &tags, const Bytes &src, size_t n, unsigned bits, bool left, bool arithmetic,
                   bool rotate) {
    Bytes dst{};
    unsigned width = n * 8;
    bits &= n == 8 ? 63 : 31;
    if (rotate)
        bits %= width;
    for (unsigned out = 0; out < width; ++out) {
        int in = left ? int(out) - int(bits) : int(out) + int(bits);
        if (rotate)
            in = (in + width) % width;
        else if (arithmetic && in >= int(width))
            in = width - 1;
        if (in >= 0 && in < int(width))
            dst[out / 8] = tags.join(dst[out / 8], src[in / 8]);
    }
    return dst;
}
} // namespace pre
