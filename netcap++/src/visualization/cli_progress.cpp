#include "network-capture/visualization/cli_progress.hpp"
#include <ostream>

#include <iostream>
#include <thread>

using namespace std;
void
CliProgress::process()
{
    while (true) {
        if (this->file_size.has_value()) {
            cout << "Captured " << this->importer->get_captured_bytes()
                 << " bytes of at most " << this->file_size.value() << " bytes"
                 << endl;
        } else {
            cout << "Captured " << this->importer->get_captured_bytes()
                 << " bytes" << endl;
        }

        if (this->importer->get_stopped()) {
            cout << "Capturing finished, processing remaining packets" << endl;
            return;
        }
        this_thread::sleep_for(this->update_intervall);
    }
}
