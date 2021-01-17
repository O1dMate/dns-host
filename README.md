# What is this?

This is a simple, lightweight DNS server written in pure JavaScript with no external dependencies. This server allows you to receive and respond to DNS queries.

The server supports capturing of requests for all common DNS record types (and more):
 - A
 - AAAA
 - NS
 - TXT
 - MX
 - CNAME

The server supports sending responses for following record types:
 - A
 - AAAA
 - TXT
 - NS

<br>

# Installation
```
npm i dns-host
```

<br>

# Usage

1. Install & import the library.
2. Create a new instance of the DNS Server.
3. Setup desired callbacks listeners (see below).
4. Start the server.
5. Respond to desired requests.

There are 4 callbacks that you can setup for the server (all of which are optional):
 * `request` - Called when a DNS request is received. The processed data will be returned as an Object. You can respond to the DNS Query by returning a value at the end of this callback function.
 * `error` - Called whenever an error is thrown by the server. The error object is returned.
 * `start` - Called when the DNS server is started.
 * `stop` - Called when the DNS server is stopped.

`Note`: Stopping the server then starting it again is totally fine and supported. All your previously setup callbacks will still work after the server has been stopped and started again.

<br>

## Listening for DNS Queries (All Record Types)
```javascript
const DnsServer = require('dns-host');
const dnsServer = new DnsServer();

dnsServer.on('request', (data) => {
    console.log('Data:', data);
    // Examples:
    // Data: { domain: 'test.com', recordType: 'A', id: 12, fromIp: '1.2.3.4' }
    // Data: { domain: 'test.com', recordType: 'AAAA', id: 13, fromIp: '1.2.3.4' }
    // Data: { domain: 'random.com', recordType: 'MX', id: 14, fromIp: '1.2.3.4' }
    // Data: { domain: 'example.com', recordType: 'NS', id: 15, fromIp: '1.2.3.4' }

    return '1.1.1.1';
})

dnsServer.on('error', (err) => {
    console.log('An Error Occurred:', err);
})

dnsServer.on('start', () => {
    console.log('DNS server started');
});

dnsServer.on('stop', () => {
    console.log('DNS server stopped');
});

dnsServer.start();

// This will stop the server.
// dnsServer.stop();
```

<br>

## Responding to DNS Queries (A Records)
```javascript
dnsServer.on('request', (data) => {
    console.log('Data:', data);
    // Example:
    // Data: { domain: 'test.com', recordType: 'A', id: 12, fromIp: '1.2.3.4' }

    // Respond with a single IPv4 Address
    return '1.2.3.4';
})
```

```javascript
dnsServer.on('request', (data) => {
    console.log('Data:', data);
    // Example:
    // Data: { domain: 'example.com', recordType: 'A', id: 24, fromIp: '1.2.3.4' }

    // Respond with a list of IPv4 Addresses
    return ['1.2.3.4', '5.6.7.8'];
})
```

<br>

## Responding to DNS Queries (AAAA Records)
```javascript
dnsServer.on('request', (data) => {
    console.log('Data:', data);
    // Example:
    // Data: { domain: 'example.com', recordType: 'AAAA', id: 12, fromIp: '1.2.3.4' }

    // Respond with a single IPv6 Address
    return '2001:db8:1111:2222:3333::51';
})
```

```javascript
dnsServer.on('request', (data) => {
    console.log('Data:', data);
    // Example:
    // Data: { domain: 'example.com', recordType: 'AAAA', id: 24, fromIp: '1.2.3.4' }

    // Respond with a list of IPv6 Addresses
    return ['2001:db8:1111:2222:3333::51', '::1', '2001:db8::ff00:42:8329'];
})
```

<br>

## Responding to DNS Queries (TXT Records)
```javascript
dnsServer.on('request', (data) => {
    console.log('Data:', data);
    // Example:
    // Data: { domain: 'example.com', recordType: 'TXT', id: 12, fromIp: '1.2.3.4' }

    // Respond with a single string
    return 'Test String 1';
})
```

```javascript
dnsServer.on('request', (data) => {
    console.log('Data:', data);
    // Example:
    // Data: { domain: 'example.com', recordType: 'TXT', id: 24, fromIp: '1.2.3.4' }

    // Respond with a list of strings
    return ['Test String 1', 'Chars: 1234567890!@#$%^&*()_+-=[]'];
})
```

<br>

## Responding to DNS Queries (NS Records)
```javascript
dnsServer.on('request', (data) => {
    console.log('Data:', data);
    // Example:
    // Data: { domain: 'example.com', recordType: 'NS', id: 12, fromIp: '1.2.3.4' }

    // Respond with a single string
    return 'ns1.example.com';
})
```

```javascript
dnsServer.on('request', (data) => {
    console.log('Data:', data);
    // Example:
    // Data: { domain: 'example.com', recordType: 'NS', id: 24, fromIp: '1.2.3.4' }

    // Respond with a list of strings
    return ['ns1.example.com', 'ns2.example.com'];
})
```

<br>

# Options
 * `importantRecordTypes` - The DNS request must be one of these types otherwise it will not call the `request` callback. Good if you only care about certain record types. Default value is that all received queries will call the `request` callback.

```javascript
const DnsServer = require('dns-host');

const dnsServer = new DnsServer({
    importantRecordTypes: ['A', 'AAAA']
    /*
         - Only 'A' and 'AAAA' record types will call the 'request' callback.
         - If any other record types are requested, the callback will NOT be called.
    */
});

dnsServer.on('request', (data) => {
    console.log('Data:', data);
    // Examples:
    // Data: { domain: 'test.com', recordType: 'A', id: 12, fromIp: '1.2.3.4' }
    // Data: { domain: 'test.com', recordType: 'AAAA', id: 13, fromIp: '1.2.3.4' }

    return '1.2.3.4';
})
```


 * `localhostOnly` - The DNS server will listen only on localhost (`127.0.0.1`) instead of on all interfaces (`0.0.0.0`). Default value is to listen on all interfaces (`0.0.0.0`).

```javascript
const DnsServer = require('dns-host');

const dnsServer = new DnsServer({
    localhostOnly: true
});
```


 * `extendedMode` - Return all the decoded information from the DNS header in the 'request' callback. Default value is non-extended mode.

```javascript
const DnsServer = require('dns-host');

const dnsServer = new DnsServer({
    extendedMode: true
});

dnsServer.on('request', (data) => {
    console.log('Data:', data);
    // Example:
    /*
    Data: {
    domain: 'example.com',
    recordType: 'A',     
    id: 13,
    recordClass: 1,      
    requestFlags: {      
        QR: 0,
        Opcode: 0,
        AA: 0,
        TC: 0,
        RD: 1,
        RA: 0,
        Z: 0,
        AD: 0,
        CD: 0,
        Rcode: 0
    },
    totalQuestions: 1,
    totalAnswers: 0,
    totalAuthority: 0,
    totalAdditional: 0,
    fromIp: '127.0.0.1'
    }
    */

    return '1.2.3.4';
})
```

<br>

# How can I test it?

You can use the `nslookup` tool that is built into windows to test all of the of the functionality of this package.

You can perform DNS queries in `nslookup` using the following commands in the command prompt:

```bash
nslookup                    # Open `nslookup`
server 127.0.0.1            # Set the IP of the DNS server
set type=<record-type>      # Specify what record type you want to retrieve
example.com                 # Enter a domain you want to retrieve the record for.
```
 - Where `<record-type>` is (a, aaaa, txt, ns, mx, etc...)


<br>

# Issues & TODO
 * IPv6 address validation is not fully done.
 * No TCP server.
 * No length enforcement. If a large payload is given for a TXT record, or too many IP addresses are returned for an A or AAAA record, the response will be received incorrectly.