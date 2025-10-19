#ifndef H_SRC_UTILS_RING_H
#define H_SRC_UTILS_RING_H

#include <array>
#include <cassert>
#include <cstddef>
#include <iterator>
#include <vector>
#include <utility>

#include "utils/alias.h"

namespace utils::ring_buffer {

template <typename T, std::size_t N>
class RingBuffer {
    static_assert(N > 0, "N must be > 0");
    std::array<T, N> buf_;
    std::size_t write_ = 0;
    std::size_t count_ = 0;

    [[nodiscard]] constexpr std::size_t oldest_index() const noexcept {
        return (write_ + N - count_) % N;
    }

    [[nodiscard]] constexpr std::size_t index_from_logical(
        std::size_t i) const noexcept {
        return (oldest_index() + i) % N;
    }

public:
    using value_type = T;
    using size_type = std::size_t;

    RingBuffer() = default;

    void push(const T &v) {
        buf_[write_] = v;
        write_ = (write_ + 1) % N;
        if (count_ < N) ++count_;
    }
    void push(T &&v) {
        buf_[write_] = std::move(v);
        write_ = (write_ + 1) % N;
        if (count_ < N) ++count_;
    }

    template <typename... Args>
    void emplace(Args &&...args) {
        buf_[write_] = T(std::forward<Args>(args)...);
        write_ = (write_ + 1) % N;
        if (count_ < N) ++count_;
    }

    T &get(size_type i) {
        assert(i < count_);
        return buf_[index_from_logical(i)];
    }
    const T &get(size_type i) const {
        assert(i < count_);
        return buf_[index_from_logical(i)];
    }

    T &operator[](size_type i) { return get(i); }
    const T &operator[](size_type i) const { return get(i); }

    const T &latest() const {
        assert(count_ > 0);
        std::size_t idx = (write_ + N - 1) % N;
        return buf_[idx];
    }
    T &latest() {
        assert(count_ > 0);
        std::size_t idx = (write_ + N - 1) % N;
        return buf_[idx];
    }

    [[nodiscard]] constexpr size_type size() const noexcept { return count_; }
    [[nodiscard]] constexpr size_type capacity() const noexcept { return N; }
    [[nodiscard]] constexpr bool empty() const noexcept { return count_ == 0; }
    [[nodiscard]] constexpr bool full() const noexcept { return count_ == N; }

    void clear() noexcept {
        write_ = 0;
        count_ = 0;
    }

    std::vector<T> to_vector() const {
        std::vector<T> v;
        v.reserve(count_);
        for (size_type i = 0; i < count_; ++i) v.push_back(get(i));
        return v;
    }

    class const_iterator {
        const RingBuffer *parent_;
        std::size_t pos_;

    public:
        using iterator_category = std::forward_iterator_tag;
        using value_type = T;
        using difference_type = std::ptrdiff_t;
        using pointer = const T *;
        using reference = const T &;

        const_iterator(const RingBuffer *p, std::size_t pos) noexcept
            : parent_(p), pos_(pos) {}
        reference operator*() const { return parent_->get(pos_); }
        pointer operator->() const { return &parent_->get(pos_); }
        const_iterator &operator++() {
            ++pos_;
            return *this;
        }
        const_iterator operator++(int) {
            const_iterator tmp = *this;
            ++*this;
            return tmp;
        }
        bool operator==(const const_iterator &o) const noexcept {
            return parent_ == o.parent_ && pos_ == o.pos_;
        }
        bool operator!=(const const_iterator &o) const noexcept {
            return !(*this == o);
        }
    };

    class iterator {
        RingBuffer *parent_;
        std::size_t pos_;

    public:
        using iterator_category = std::forward_iterator_tag;
        using value_type = T;
        using difference_type = std::ptrdiff_t;
        using pointer = T *;
        using reference = T &;

        iterator(RingBuffer *p, std::size_t pos) noexcept
            : parent_(p), pos_(pos) {}
        reference operator*() const { return parent_->get(pos_); }
        pointer operator->() const { return &parent_->get(pos_); }
        iterator &operator++() {
            ++pos_;
            return *this;
        }
        iterator operator++(int) {
            iterator tmp = *this;
            ++*this;
            return tmp;
        }
        bool operator==(const iterator &o) const noexcept {
            return parent_ == o.parent_ && pos_ == o.pos_;
        }
        bool operator!=(const iterator &o) const noexcept {
            return !(*this == o);
        }
    };

    iterator begin() noexcept { return iterator(this, 0); }
    iterator end() noexcept { return iterator(this, count_); }
    const_iterator begin() const noexcept { return const_iterator(this, 0); }
    const_iterator end() const noexcept { return const_iterator(this, count_); }
    const_iterator cbegin() const noexcept { return const_iterator(this, 0); }
    const_iterator cend() const noexcept {
        return const_iterator(this, count_);
    }
};
}  // namespace utils::ring_buffer

#endif  // H_SRC_UTILS_RING_H
