#include "ore/large_ore.hpp"
#include "ore/range_query.hpp"
#include "ore/small_ore.hpp"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <random>
#include <vector>

using namespace ore;

int main() {
    {
        auto sk = small_setup(64);
        std::mt19937 gen(7);
        std::uniform_int_distribution<std::uint32_t> dist(0, 63);
        for (int i = 0; i < 300; ++i) {
            std::uint32_t x = dist(gen);
            std::uint32_t y = dist(gen);
            int got = small_compare(small_encrypt_left(sk, x), small_encrypt_right(sk, y));
            assert(got == cmp3(x, y));
        }
    }

    {
        auto sk = large_setup(256, 4);
        std::mt19937 gen(42);
        std::uniform_int_distribution<std::uint32_t> dist(0, 0xFFFFFFFFu);
        for (int i = 0; i < 80; ++i) {
            std::uint32_t x = dist(gen);
            std::uint32_t y = dist(gen);
            int got = large_compare(large_encrypt_left(sk, x), large_encrypt_right(sk, y));
            assert(got == cmp3(x, y));
        }

        std::uint32_t y = 0x00FF10AAu;
        auto ct_r = large_encrypt_right(sk, y);
        assert(large_decrypt(sk, ct_r, 0, 0xFFFFFFFFu) == y);
    }

    {
        auto sk = large_setup(256, 4);
        RangeQueryClient client(sk, 0, 0xFFFFFFFFu);
        RangeQueryServer server(sk);

        std::vector<std::uint32_t> plain = {9, 1, 5, 2, 7, 3, 10};
        server.setup(client.setup_token(plain));

        auto [l, r] = client.range_token(3, 8);
        auto response = client.decode_response(server.range_query(l, r));
        std::vector<std::uint32_t> expected = {3, 5, 7};
        assert(response == expected);

        auto ins = client.insert_token(6);
        server.insert(ins.first, ins.second);

        auto [l2, r2] = client.range_token(3, 8);
        auto response2 = client.decode_response(server.range_query(l2, r2));
        std::vector<std::uint32_t> expected2 = {3, 5, 6, 7};
        assert(response2 == expected2);

        auto del = client.delete_token(6);
        assert(server.remove_one(del.first, del.second));
    }

    std::cout << "All C++ checks passed.\n";
    return 0;
}
