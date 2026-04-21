#include "ore/large_ore.hpp"
#include "ore/range_query.hpp"
#include "ore/small_ore.hpp"

#include <iostream>
#include <vector>

using namespace ore;

int main() {
    auto ssk = small_setup(32);
    auto ct_l = small_encrypt_left(ssk, 7);
    auto ct_r = small_encrypt_right(ssk, 11);
    std::cout << "small compare(7,11) cmp3=" << small_compare(ct_l, ct_r) << "\n";

    auto lsk = large_setup(256, 4);
    std::uint32_t x = 12345678, y = 22345678;
    std::cout << "large compare(x,y)="
              << large_compare(large_encrypt_left(lsk, x), large_encrypt_right(lsk, y))
              << "\n";

    RangeQueryClient client(lsk, 0, 0xFFFFFFFFu);
    RangeQueryServer server(lsk);
    std::vector<std::uint32_t> db = {3, 1, 7, 4, 5};
    server.setup(client.setup_token(db));

    auto [left_lo, left_hi] = client.range_token(3, 5);
    auto plain = client.decode_response(server.range_query(left_lo, left_hi));
    std::cout << "range [3,5] result count=" << plain.size() << "\n";

    return 0;
}
