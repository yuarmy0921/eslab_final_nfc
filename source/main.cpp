/* Sockets Example
 * Copyright (c) 2016-2020 ARM Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ThisThread.h"
#include "PinNames.h"
#include "mbed.h"
#include "nsapi_types.h"
#include "../include/wifi_helper.h"
#include "mbed-trace/mbed_trace.h"

#include <cstdint>
#include "Callback.h"
#include "DigitalInOut.h"
#include "DigitalOut.h"
#include "ThisThread.h"
#include "events/EventQueue.h"

// NFC
#include "MessageParser.h"
#include "NFCEEPROMDriver.h"
#include "Record.h"
#include "nfc/ndef/MessageBuilder.h"
#include "nfc/ndef/MessageParser.h"
#include "nfc/ndef/common/SimpleMessageParser.h"
#include "nfc/ndef/common/URI.h"
#include "nfc/ndef/common/util.h"

#include "NFC.h"
#include "NFCEEPROM.h"
#include "EEPROMDriver.h"
#include <cstdio>

#define MAXIMUM_BUFFER_SIZE 32

// wifi
#define HOSTNAME "192.168.43.36"

using events::EventQueue;

// NFC
using mbed::nfc::NFCEEPROM;
using mbed::nfc::NFCEEPROMDriver;
using mbed::Span;

using mbed::nfc::ndef::MessageBuilder;
using mbed::nfc::ndef::MessageParser;

using mbed::nfc::ndef::Record;
using mbed::nfc::ndef::RecordType;
using mbed::nfc::ndef::RecordID;

using mbed::nfc::ndef::common::SimpleMessageParser;
using mbed::nfc::ndef::common::URI; // uri
using mbed::nfc::ndef::common::Text; // text
using mbed::nfc::ndef::common::Mime;
using mbed::nfc::ndef::common::span_from_cstr;


/* URL that will be written into the tag */
const char url_string[] = "mbed.com";

#if MBED_CONF_APP_USE_TLS_SOCKET
#include "root_ca_cert.h"

#ifndef DEVICE_TRNG
#error "mbed-os-example-tls-socket requires a device which supports TRNG"
#endif
#endif // MBED_CONF_APP_USE_TLS_SOCKET

char ndef_msg[32];
int ndef_len;
bool volatile finished = false;
char goal_str[8] = "NFC: f\n";

Mutex mutex;
ConditionVariable cond(mutex);

struct ParserDelegate: SimpleMessageParser::Delegate {
    virtual void on_parsing_started()
    {
        printf("parsing started\r\n");
    }

    virtual void on_text_parsed(const Text &text, const RecordID &)
    {
        // printf("Text record parsed.\r\n");
        // printf(
        //     "\tlanguage: %.*s\r\n",
        //     text.get_language_code().size(), text.get_language_code().data()
        // );
        // printf("\ttext: %.*s\r\n",  text.get_text().size(), text.get_text().data());
        ndef_len = sprintf(ndef_msg, "NFC: %.*s\n", text.get_text().size(), text.get_text().data());
        
        bool match = true;
        mutex.lock();
        if (!finished) {
            for (int i = 0; i < sizeof(goal_str)/sizeof(char); i++) {
                printf("str: %d, %d\n", goal_str[i], ndef_msg[i]);
                match &= (ndef_msg[i] == goal_str[i]);
            } 
            if (match) {
                finished = true;
                
                cond.notify_all();
            }
            printf("finished: %d\n", finished);
        }
        mutex.unlock();
        printf("length: %d\n", sizeof(ndef_msg) / sizeof(char));
    }

    virtual void on_uri_parsed(const URI &uri, const RecordID &)
    {
        printf("URI parsed.\r\n");
        printf("\tid: %d\r\n", uri.get_id());
        printf("\tvalue: %.*s\r\n",  uri.get_uri_field().size(), uri.get_uri_field().data());
    }

    virtual void on_mime_parsed(const Mime &mime, const RecordID &)
    {
        printf("Mime object parsed.\r\n");
        printf("\ttype: %.*s\r\n", mime.get_mime_type().size(), mime.get_mime_type().data());
        printf("\tcontent size: %d\r\n", mime.get_mime_content().size());
    }

    virtual void on_unknown_record_parsed(const Record &record)
    {
        printf("Unknown record parsed.\r\n");
        printf(
            "\ttype: %d, type_value: %.*s\r\n",
            record.type.tnf, record.type.value.size(), record.type.value.data()
        );
        printf(
            "\tpayload size: %d, payload: %.*s\r\n",
            record.payload.size(), record.payload.size(), record.payload.data()
        );
    }

    virtual void on_parsing_terminated()
    {
        printf("parsing terminated\r\n");
    }

    virtual void on_parsing_error(MessageParser::error_t error)
    {
        printf("Parsing error: %d\r\n", error);
    }
};

class EEPROMExample : mbed::nfc::NFCEEPROM::Delegate
{
public:
    EEPROMExample(events::EventQueue& queue, NFCEEPROMDriver& eeprom_driver) :
        _ndef_buffer(),
        _eeprom(&eeprom_driver, &queue, _ndef_buffer),
        _queue(queue),
        _parser(),
        _delegate()
    { }

    void initialize() {
        if (_eeprom.initialize() != NFC_OK) {
            printf("failed to initialise\r\n");
            _queue.break_dispatch();
        }

        _eeprom.set_delegate(this); //NFCEEPROM
        _parser.set_delegate(&_delegate);  // SimpleMessageParser
    }

    void update() {
        _queue.call(&_eeprom, &NFCEEPROM::read_ndef_message);
    }
 
    void run() {
        if (_eeprom.initialize() != NFC_OK) {
            printf("failed to initialise\r\n");
            _queue.break_dispatch();
        }

        _eeprom.set_delegate(this); //NFCEEPROM
        _parser.set_delegate(&_delegate);  // SimpleMessageParser

        _queue.call(&_eeprom, &NFCEEPROM::read_ndef_message);
        _queue.dispatch_forever();
        
    }

private:
    virtual void on_ndef_message_written(nfc_err_t result) {
        if (result == NFC_OK) {
            printf("message written successfully\r\n");
        } else {
            printf("failed to write (error: %d)\r\n", result);
        }

        // _queue.call(&_eeprom, &NFCEEPROM::read_ndef_message);
    }

    virtual void on_ndef_message_read(nfc_err_t result) {
        if (result == NFC_OK) {
            printf("message read successfully\r\n");

        } else {
            printf("failed to read (error: %d)\r\n", result);
        }

        ThisThread::sleep_for(500);
        // _queue.call(&_eeprom, &NFCEEPROM::erase_ndef_message);
        _queue.call(&_eeprom, &NFCEEPROM::read_ndef_message);
        
    }

    virtual void on_ndef_message_erased(nfc_err_t result) {
        printf("Erase result: %d\n", result);
    }

    virtual void parse_ndef_message(const Span<const uint8_t> &buffer) {
        printf("Received an ndef message of size %d\r\n", buffer.size());
        if (buffer.size() > 0) _parser.parse(buffer); // Parse NDEF message
    }

    virtual size_t build_ndef_message(const Span<uint8_t> &buffer) {
        printf("Building an ndef message\r\n");

        /* create a message containing the URL */

        MessageBuilder builder(buffer);

        /* URI expected a non-null terminated string  so we use a helper function that casts
         * the pointer into a Span of size smaller by one */
        URI uri(URI::HTTPS_WWW, span_from_cstr(url_string));

        uri.append_as_record(builder, true);

        return builder.get_message().size();
    }

private:
    uint8_t _ndef_buffer[2048];
    NFCEEPROM _eeprom;
    EventQueue& _queue;

    SimpleMessageParser _parser;
    ParserDelegate _delegate;
};

class SocketDemo {
    static constexpr size_t MAX_NUMBER_OF_ACCESS_POINTS = 10;
    static constexpr size_t MAX_MESSAGE_RECEIVED_LENGTH = 100;

/*
#if MBED_CONF_APP_USE_TLS_SOCKET
    static constexpr size_t REMOTE_PORT = 443; // tls port
#else
    static constexpr size_t REMOTE_PORT = 80; // standard HTTP port
#endif // MBED_CONF_APP_USE_TLS_SOCKET
*/

static constexpr size_t REMOTE_PORT = 6531;

public:    
    SocketDemo() : _net(NetworkInterface::get_default_instance())
    {
        
    }

    ~SocketDemo()
    {
        if (_net) {
            _net->disconnect();
        }
    }

    void run()
    {
        mutex.lock();
        do {
            ThisThread::sleep_for(500);
            printf("sleep\n");
            cond.wait();
        } while (!finished);
        printf("finished: %d\n", finished);
        int response = _socket.send(ndef_msg, ndef_len);
        printf("response: %d\n", response);
        mutex.unlock();
    }

    void connect() {
        while (!_net) {
            printf("Error! No network interface found.\r\n");
            return;
        }

        /* if we're using a wifi interface run a quick scan */
        if (_net->wifiInterface()) {
            /* the scan is not required to connect and only serves to show visible access points */
            wifi_scan();

            /* in this example we use credentials configured at compile time which are used by
             * NetworkInterface::connect() but it's possible to do this at runtime by using the
             * WiFiInterface::connect() which takes these parameters as arguments */
        }

        /* connect will perform the action appropriate to the interface type to connect to the network */

        printf("Connecting to the network...\r\n");

        // nsapi_size_or_error_t result = _net->connect();
        nsapi_size_or_error_t result;
        while ((result = _net->connect()) != 0) {
            printf("Error! _net->connect() returned: %d\r\nreconnect", result);
        }

        print_network_info();

        /* opening the socket only allocates resources */
        // result = _socket.open(_net);
        while ((result = _socket.open(_net)) != 0) {
            printf("Error! _socket.open() returned: %d\r\n", result);
        }

#if MBED_CONF_APP_USE_TLS_SOCKET
        result = _socket.set_root_ca_cert(root_ca_cert);
        if (result != NSAPI_ERROR_OK) {
            printf("Error: _socket.set_root_ca_cert() returned %d\n", result);
            return;
        }
        _socket.set_hostname(HOSTNAME);
#endif // MBED_CONF_APP_USE_TLS_SOCKET

        /* now we have to find where to connect */
        SocketAddress address;
        //const char* IP = "192.168.50.226";
        //address.set_ip_address(IP);

        if (!resolve_hostname(address)) {
            return;
        }

        address.set_port(REMOTE_PORT);

        /* we are connected to the network but since we're using a connection oriented
         * protocol we still need to open a connection on the socket */

        printf("Opening connection to remote port %d\r\n", REMOTE_PORT);

        while((result = _socket.connect(address)) != 0){
            // ThisThread::sleep_for(1000);
            printf("Error! _socket.connect() returned: %d\r\n", result);

        };
        /*
        printf("%d", result);
        if (result != 0) {
            printf("Error! _socket.connect() returned: %d\r\n", result);
            return;
        }
        */
        printf("Demo concluded successfully \r\n");
    }

private:
    bool resolve_hostname(SocketAddress &address)
    {
        const char hostname[] = HOSTNAME;

        /* get the host address */
        printf("\nResolve hostname %s\r\n", hostname);
        nsapi_size_or_error_t result = _net->gethostbyname(hostname, &address);
        if (result != 0) {
            printf("Error! gethostbyname(%s) returned: %d\r\n", hostname, result);
            return false;
        }

        printf("%s address is %s\r\n", hostname, (address.get_ip_address() ? address.get_ip_address() : "None") );

        return true;
    }

    bool send_http_request()
    {
        /* loop until whole request sent */
        const char buffer[] = "GET / HTTP/1.1\r\n"
                              "Host: ifconfig.io\r\n"
                              "Connection: close\r\n"
                              "\r\n";

        nsapi_size_t bytes_to_send = strlen(buffer);
        nsapi_size_or_error_t bytes_sent = 0;

        printf("\r\nSending message: \r\n%s", buffer);

        while (bytes_to_send) {
            bytes_sent = _socket.send(buffer + bytes_sent, bytes_to_send);
            if (bytes_sent < 0) {
                printf("Error! _socket.send() returned: %d\r\n", bytes_sent);
                return false;
            } else {
                printf("sent %d bytes\r\n", bytes_sent);
            }

            bytes_to_send -= bytes_sent;
        }

        printf("Complete message sent\r\n");

        return true;
    }

    bool receive_http_response()
    {
        char buffer[MAX_MESSAGE_RECEIVED_LENGTH];
        int remaining_bytes = MAX_MESSAGE_RECEIVED_LENGTH;
        int received_bytes = 0;

        /* loop until there is nothing received or we've ran out of buffer space */
        nsapi_size_or_error_t result = remaining_bytes;
        while (result > 0 && remaining_bytes > 0) {
            result = _socket.recv(buffer + received_bytes, remaining_bytes);
            if (result < 0) {
                printf("Error! _socket.recv() returned: %d\r\n", result);
                return false;
            }

            received_bytes += result;
            remaining_bytes -= result;
        }

        /* the message is likely larger but we only want the HTTP response code */

        printf("received %d bytes:\r\n%.*s\r\n\r\n", received_bytes, strstr(buffer, "\n") - buffer, buffer);

        return true;
    }

    void wifi_scan()
    {
        WiFiInterface *wifi = _net->wifiInterface();

        WiFiAccessPoint ap[MAX_NUMBER_OF_ACCESS_POINTS];

        /* scan call returns number of access points found */
        int result = wifi->scan(ap, MAX_NUMBER_OF_ACCESS_POINTS);

        if (result <= 0) {
            printf("WiFiInterface::scan() failed with return value: %d\r\n", result);
            return;
        }

        printf("%d networks available:\r\n", result);

        for (int i = 0; i < result; i++) {
            printf("Network: %s secured: %s BSSID: %hhX:%hhX:%hhX:%hhx:%hhx:%hhx RSSI: %hhd Ch: %hhd\r\n",
                   ap[i].get_ssid(), get_security_string(ap[i].get_security()),
                   ap[i].get_bssid()[0], ap[i].get_bssid()[1], ap[i].get_bssid()[2],
                   ap[i].get_bssid()[3], ap[i].get_bssid()[4], ap[i].get_bssid()[5],
                   ap[i].get_rssi(), ap[i].get_channel());
        }
        printf("\r\n");
    }

    void print_network_info()
    {
        /* print the network info */
        SocketAddress a;
        _net->get_ip_address(&a);
        printf("IP address: %s\r\n", a.get_ip_address() ? a.get_ip_address() : "None");
        _net->get_netmask(&a);
        printf("Netmask: %s\r\n", a.get_ip_address() ? a.get_ip_address() : "None");
        _net->get_gateway(&a);
        printf("Gateway: %s\r\n", a.get_ip_address() ? a.get_ip_address() : "None");
    }

private:
    NetworkInterface *_net;

#if MBED_CONF_APP_USE_TLS_SOCKET
    TLSSocket _socket;
#else
    TCPSocket _socket;
#endif // MBED_CONF_APP_USE_TLS_SOCKET
};

int main() {
    Thread socket_t;
    Thread nfc_t;

#ifdef MBED_CONF_MBED_TRACE_ENABLE
    mbed_trace_init();
#endif
    SocketDemo *socket_example = new SocketDemo();
    MBED_ASSERT(socket_example);

    EventQueue NFCqueue;
    NFCEEPROMDriver& eeprom_driver = get_eeprom_driver(NFCqueue);
    EEPROMExample nfc_example(NFCqueue, eeprom_driver);

    socket_example->connect();
    socket_t.start(callback(socket_example, &SocketDemo::run));
    nfc_t.start(callback(&nfc_example, &EEPROMExample::run));
    while (1);
}
