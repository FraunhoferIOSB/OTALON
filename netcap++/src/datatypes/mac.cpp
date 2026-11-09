#include "network-capture/datatypes/mac.hpp"

#include <cstring>

using namespace std;
MAC::MAC(const uint8_t* buff)
{
    set_mac(buff);
}

MAC&
MAC::operator=(const MAC& other)
{
    memcpy(&this->mac, &other.mac, sizeof(this->mac));
    return *this;
}

bool
MAC::operator==(const MAC& other) const
{
    auto cmp = memcmp(&this->mac, &other.mac, sizeof(this->mac));
    return cmp == 0;
}

std::string
MAC::to_string() const
{
    char buff[18];
    sprintf(buff,
            "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5]);

    return { buff };
}
void
MAC::set_mac(const uint8_t* buff)
{
    memcpy(&this->mac, buff, sizeof(this->mac));
}

const uint8_t*
MAC::get_mac() const
{
    return this->mac;
}
