/**
 * Hello, world 1
 */

#include <filesystem>
#include <iostream>

using namespace std;
namespace fs = std::filesystem;

int main() {
    cout << "[stdout] Hello, world!" << endl;
    cerr << "[stderr] Hello, world!" << endl;

    cout << "List /:" << endl;
    for (auto &entry : fs::directory_iterator("/")) {
        cout << "  " << entry.path() << endl;
    }

    return 0;
}
