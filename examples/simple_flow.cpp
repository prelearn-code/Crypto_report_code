#include <iostream>
#include <vector>

#include "ore/large_ore.hpp"
#include "ore/range_query.hpp"

int main() {
    ore::LargeORE ore = ore::LargeORE::setup(8, 4);
    ore::RangeClient client(ore);
    ore::RangeServer server;

    std::vector<ore::PlainRecord> initial = {
        {1, 7},
        {2, 11},
        {3, 21},
        {4, 15},
        {5, 27},
    };

    server.load(client.setupDatabase(initial));

    auto firstToken = client.rangeToken(10, 20);
    auto firstRecords = client.decryptRecords(server.range(firstToken));

    std::cout << "range [10, 20]:" << '\n';
    for (const auto& record : firstRecords) {
        std::cout << "  id=" << record.id << ", value=" << record.value << '\n';
    }

    server.insert(client.insertToken(6, 18));
    server.eraseEqual(client.deleteToken(11));

    auto secondToken = client.rangeToken(10, 20);
    auto secondRecords = client.decryptRecords(server.range(secondToken));

    std::cout << "after insert 18 and delete 11:" << '\n';
    for (const auto& record : secondRecords) {
        std::cout << "  id=" << record.id << ", value=" << record.value << '\n';
    }

    return 0;
}
