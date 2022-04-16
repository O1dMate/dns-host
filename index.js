const dgram = require('dgram');
const net = require('net');
const isIPv4 = net.isIPv4;
const isIPv6 = net.isIPv6;

const RECORD_ID_TO_TYPE_LOOKUP = {
    1: 'A',
    2: 'NS',
    3: 'MD',
    4: 'MF',
    5: 'CNAME',
    6: 'SOA',
    7: 'MB',
    8: 'MG',
    9: 'MR',
    10: 'NULL',
    11: 'WKS',
    12: 'PTR',
    13: 'HINFO',
    14: 'MINFO',
    15: 'MX',
    16: 'TXT',
    17: 'RP',
    18: 'AFSDB',
    19: 'X25',
    20: 'ISDN',
    21: 'RT',
    22: 'NSAP',
    23: 'NSAP-PTR',
    24: 'SIG',
    25: 'KEY',
    26: 'PX',
    27: 'GPOS',
    28: 'AAAA',
};

const RECORD_TYPE_TO_ID_LOOKUP = {};

const expandIpv6Address = (ipAddress) => {
    let pieces = ipAddress.split(':');

    if (pieces.length < 8) {
        let newPieces = [];
        let handledEmptyPiece = false;
        let indexToInsertAt = -1;

        // Determine where the double colon (::) was and stored that location so the zeros can be added back in.
        for (let i = 0; i < pieces.length; ++i) {
            if (!handledEmptyPiece && pieces[i] === '') {
                indexToInsertAt = i;
                handledEmptyPiece = true;
                newPieces.push('0');
            }

            if (pieces[i] !== '') newPieces.push(pieces[i]);
        }

        // Add the inbetween zeros that were removed.
        while (newPieces.length < 8) {
            newPieces.splice(indexToInsertAt, 0, '0');
        }

        pieces = newPieces;
    }

    // Ensure each piece of the address contains 4 Hex chars
    return pieces.map(currentPiece => currentPiece.padStart(4, '0')).join(':');
}


const decodesFlagsAndCodes = (flagsAndCodes) => {
    if (!Number.isInteger(parseInt(flagsAndCodes))) throw new Error("DNS Decode Failed: Flags & Codes not a valid Integer");

    return {
        QR: (flagsAndCodes & 32768) >> 15,
        Opcode: (flagsAndCodes & (16384 + 8192 + 4096 + 2048)) >> 11,
        AA: (flagsAndCodes & 1024) >> 10,
        TC: (flagsAndCodes & 512) >> 9,
        RD: (flagsAndCodes & 256) >> 8,
        RA: (flagsAndCodes & 128) >> 7,
        Z: (flagsAndCodes & 64) >> 6,
        AD: (flagsAndCodes & 32) >> 5,
        CD: (flagsAndCodes & 16) >> 4,
        Rcode: (flagsAndCodes & (8 + 4 + 2 + 1)) >> 0,
    };
}

// rawMessageData = Uint8Array of the DNS request
const decodeRequest = (rawMessageData, extendedMode) => {
    if (rawMessageData.length < 12) throw new Error("DNS Decode Failed: Request not long enough < 8 bytes");

    // Convert from Uint8Array to standard Array
    rawMessageData = Array.from(rawMessageData);

    // Identification = 2 Bytes
    let idNumber = (rawMessageData.shift() << 8) | rawMessageData.shift();

    // Flags & Codes = 2 Bytes
    let flagsAndCodes = (rawMessageData.shift() << 8) | rawMessageData.shift();
    flagsAndCodes = decodesFlagsAndCodes(flagsAndCodes);

    // Total Questions = 2 Bytes
    let totalQuestions = (rawMessageData.shift() << 8) | rawMessageData.shift();

    // Total Answers RRs = 2 Bytes
    let totalAnswers = (rawMessageData.shift() << 8) | rawMessageData.shift();

    // Total Authority RRs = 2 Bytes
    let totalAuthority = (rawMessageData.shift() << 8) | rawMessageData.shift();

    // Total Additional RRs = 2 Bytes
    let totalAdditional = (rawMessageData.shift() << 8) | rawMessageData.shift();

    // List of domains in the question section and the record type.
    let domainList = [];

    for (let questionNumber = 0; questionNumber < totalQuestions; ++questionNumber) {
        let currentDomain = [];

        // Get the length of the next piece of the domain
        let lengthOfNextPiece = rawMessageData.shift();

        while (rawMessageData.length > lengthOfNextPiece) {
            for (let i = 0; i < lengthOfNextPiece; ++i) {
                currentDomain.push(String.fromCharCode(rawMessageData[i]));
            }

            // Remove the processed information
            rawMessageData = rawMessageData.slice(lengthOfNextPiece);

            // Get the length of the next piece of the domain
            lengthOfNextPiece = rawMessageData.shift();

            // Processing of the domain is done, exit the loop
            if (lengthOfNextPiece === 0) break;
            // There is more of the domain to process
            else currentDomain.push('.');
        }

        if (rawMessageData.length < 4) throw new Error(`DNS Decode Failed: Question section not long enough < 4 bytes for "${currentDomain.join('')}`);

        // Record Type = 2 Bytes
        let recordType = (rawMessageData.shift() << 8) | rawMessageData.shift();

        // Record Class = 2 Bytes
        let recordClass = (rawMessageData.shift() << 8) | rawMessageData.shift();

        let domainData = {
            domain: currentDomain.join(''),
            recordType: RECORD_ID_TO_TYPE_LOOKUP.hasOwnProperty(recordType) ? RECORD_ID_TO_TYPE_LOOKUP[recordType] : 'N/A',
            id: idNumber,
        }

        if (extendedMode) {
            domainData.recordClass = recordClass;
            domainData.requestFlags = flagsAndCodes;
            domainData.totalQuestions = totalQuestions;
            domainData.totalAnswers = totalAnswers;
            domainData.totalAuthority = totalAuthority;
            domainData.totalAdditional = totalAdditional;
        }

        domainList.push(domainData);
    }

    return domainList;
}

const genericHeader = (id, answers, domain, recordType) => {
    let responseBuffer = '';

    // Transaction ID (2 Bytes)
    responseBuffer += id.toString(16).padStart(4, '0');

    // Flags (Standard Query Response settings = 2 Bytes [0x8180])
    responseBuffer += '8180';

    // Questions (2 Bytes)
    responseBuffer += '0001';

    // Answers (2 Bytes)
    responseBuffer += '00' + answers.toString(16).padStart(2, '0');

    // Authority RRs (2 Bytes [0x0000]) & Additional RRs (2 Bytes [0x0000])
    responseBuffer += '00000000';

    // Queries SECTION (Assuming only 1 since it's most common)
    domain.split('.').forEach(partOfDomain => {
        // Append the length of the next piece of the domain
        responseBuffer += partOfDomain.length.toString(16).padStart(2, '0');

        // Append the domain
        partOfDomain.split('').forEach(char => {
            responseBuffer += char.charCodeAt().toString(16).padStart(2, '0');
        });
    });

    // Null Terminator for domain-name
    responseBuffer += '00';

    // Record Type
    responseBuffer += '00' + RECORD_TYPE_TO_ID_LOOKUP[recordType].toString(16).padStart(2, '0');

    // Class (IN = 0x0001)
    responseBuffer += '0001';

    return responseBuffer;
}

const construct_A_Record_Response = (requestData, responseIpList) => {
    let responseBuffer = genericHeader(requestData.id, responseIpList.length, requestData.domain, 'A');

    // Answers SECTION
    responseIpList.forEach(responseIp => {
        // Name
        responseBuffer += 'c00c';

        // Record Type (A)
        responseBuffer += '00' + RECORD_TYPE_TO_ID_LOOKUP['A'].toString(16).padStart(2, '0');

        // Class (IN = 0x0001)
        responseBuffer += '0001';

        // TTL - Time to Live (4 Bytes)
        responseBuffer += '00000015';

        // Data Length
        responseBuffer += '0004';

        responseIp.split('.').forEach(x => {
            responseBuffer += parseInt(x).toString(16).padStart(2, '0');
        });
    })

    return Buffer.from(responseBuffer, 'hex');
}

const construct_AAAA_Record_Response = (requestData, responseIpList) => {
    let responseBuffer = genericHeader(requestData.id, responseIpList.length, requestData.domain, 'AAAA');

    // Answers SECTION
    responseIpList.forEach(responseIp => {
        // Name
        responseBuffer += 'c00c';

        // Record Type (AAAA)
        responseBuffer += '00' + RECORD_TYPE_TO_ID_LOOKUP['AAAA'].toString(16).padStart(2, '0');

        // Class (IN = 0x0001)
        responseBuffer += '0001';

        // TTL - Time to Live (4 Bytes)
        responseBuffer += '00000015';

        // Data Length
        responseBuffer += '0010';

        expandIpv6Address(responseIp).split(':').join('').match(/.{1,2}/g).forEach(x => {
            responseBuffer += x;
        });
    })

    return Buffer.from(responseBuffer, 'hex');
}

const construct_TXT_Record_Response = (requestData, responseTextList) => {
    let responseBuffer = genericHeader(requestData.id, responseTextList.length, requestData.domain, 'TXT');

    // Answers SECTION
    responseTextList.forEach(responseText => {
        // Name
        responseBuffer += 'c00c';

        // Record Type (TXT)
        responseBuffer += '00' + RECORD_TYPE_TO_ID_LOOKUP['TXT'].toString(16).padStart(2, '0');

        // Class (IN = 0x0001)
        responseBuffer += '0001';

        // TTL - Time to Live (4 Bytes)
        responseBuffer += '00000015';

        // Data Length (2 Bytes)
        responseBuffer += (responseText.length + 1).toString(16).padStart(4, '0');

        // TXT Length (1 Byte)
        responseBuffer += responseText.length.toString(16).padStart(2, '0');

        responseText.split('').forEach(char => {
            responseBuffer += char.charCodeAt().toString(16).padStart(2, '0');
        });
    })

    return Buffer.from(responseBuffer, 'hex');
}

const construct_NS_Record_Response = (requestData, responseServerList) => {
    let responseBuffer = genericHeader(requestData.id, responseServerList.length, requestData.domain, 'NS');

    // Answers SECTION
    responseServerList.forEach(responseServer => {
        // Name
        responseBuffer += 'c00c';

        // Record Type (NS)
        responseBuffer += '00' + RECORD_TYPE_TO_ID_LOOKUP['NS'].toString(16).padStart(2, '0');

        // Class (IN = 0x0001)
        responseBuffer += '0001';

        // TTL - Time to Live (4 Bytes)
        responseBuffer += '00000015';

        // Data Length (2 Bytes)
        responseBuffer += (responseServer.length + 3).toString(16).padStart(4, '0');

        // Append the length of sub-domain
        responseBuffer += responseServer.length.toString(16).padStart(2, '0');

        responseServer.split('').forEach(char => {
            responseBuffer += char.charCodeAt().toString(16).padStart(2, '0');
        });

        // End of Answer
        responseBuffer += 'c00c';
    })

    return Buffer.from(responseBuffer, 'hex');
}

let SERVER_SOCKET = null;
let IMPORTANT_RECORD_TYPES = null;
let EXTENDED_MODE = null;
let SERVER_PORT = null;
let LOCAL_HOST_ONLY = null;
let CALLBACK_ON_ERROR = null;
let CALLBACK_ON_REQUEST = null;
let CALLBACK_ON_START = null;
let CALLBACK_ON_STOP = null;

class DnsServer {
    constructor({ customPort, extendedMode, importantRecordTypes, localhostOnly } = { customPort: null, extendedMode: false, importantRecordTypes: false, localhostOnly: false }) {
        EXTENDED_MODE = !!extendedMode;

        LOCAL_HOST_ONLY = !!localhostOnly;

        if (importantRecordTypes && Array.isArray(importantRecordTypes)) {
            IMPORTANT_RECORD_TYPES = new Map();

            importantRecordTypes.forEach(x => {
                if (typeof (x) === 'string') IMPORTANT_RECORD_TYPES.set(x, true);
            });
        }

        if (!customPort) {
            SERVER_PORT = 53;
        } else if (!Number.isInteger(customPort)) {
            throw new Error('Custom Port is not a valid Integer');
        } else if (Number.isInteger(customPort) && (customPort < 1 || customPort > 65535)) {
            throw new Error('Custom Port must be > 0 and < 65535');
        } else {
            SERVER_PORT = customPort;
        }
    }

    on(onType, callback) {
        if (!callback || typeof (callback) !== 'function') throw new Error('Callback Must be a function');

        if (onType === 'error') {
            CALLBACK_ON_ERROR = callback;
        } else if (onType === 'request') {
            CALLBACK_ON_REQUEST = callback;
        } else if (onType === 'start') {
            CALLBACK_ON_START = callback;
        } else if (onType === 'stop') {
            CALLBACK_ON_STOP = callback;
        } else return;
    }

    start() {
        try {
            SERVER_SOCKET = dgram.createSocket('udp4');

            SERVER_SOCKET.on('message', async (message, messageInfo) => {
                try {
                    let dnsRequestData = decodeRequest(Uint8Array.from(Buffer.from(message, 'utf8')), EXTENDED_MODE);

                    dnsRequestData = dnsRequestData.filter(request => {
                        request.fromIp = messageInfo.address.toString();

                        if (!IMPORTANT_RECORD_TYPES) return true;

                        if (IMPORTANT_RECORD_TYPES && IMPORTANT_RECORD_TYPES.get(request.recordType)) {
                            return true;
                        }
                        return false;
                    });

                    if (dnsRequestData.length < 1) return;

                    if (CALLBACK_ON_REQUEST && typeof (CALLBACK_ON_REQUEST) === 'function') {
                        let domain = dnsRequestData[0].domain;
                        let id = dnsRequestData[0].id;
                        let recordType = dnsRequestData[0].recordType;
                        let responseData;

                        if (CALLBACK_ON_REQUEST.constructor.name === 'AsyncFunction') {
                            responseData = await CALLBACK_ON_REQUEST(dnsRequestData[0]);
                        } else {
                            responseData = CALLBACK_ON_REQUEST(dnsRequestData[0]);
                        }

                        if (!responseData) return;

                        let dnsResponseBuffer;

                        if (dnsRequestData[0].recordType === 'A') {
                            let singleIp = isIPv4(responseData);
                            let listOfIps = Array.isArray(responseData) ? responseData.map(x => isIPv4(x)).reduce((acum, cur) => acum && cur, true) : false;

                            if (singleIp) dnsResponseBuffer = construct_A_Record_Response(dnsRequestData[0], [responseData]);
                            else if (listOfIps) dnsResponseBuffer = construct_A_Record_Response(dnsRequestData[0], responseData);
                            else throw new Error(`DNS Response Error: Response Data is not a valid IPv4 address or list of addresses for (Domain: ${domain}, RecordType: ${recordType}, ID: ${id}).\nResponse provided: ${Array.isArray(responseData) ? JSON.stringify(responseData) : responseData}`,);
                        } else if (dnsRequestData[0].recordType === 'AAAA') {
                            let singleIp = isIPv6(responseData);
                            let listOfIps = Array.isArray(responseData) ? responseData.map(x => isIPv6(x)).reduce((acum, cur) => acum && cur, true) : false;

                            if (singleIp) dnsResponseBuffer = construct_AAAA_Record_Response(dnsRequestData[0], [responseData]);
                            else if (listOfIps) dnsResponseBuffer = construct_AAAA_Record_Response(dnsRequestData[0], responseData);
                            else throw new Error(`DNS Response Error: Response Data is not a valid IPv6 address or list of addresses for (Domain: ${domain}, RecordType: ${recordType}, ID: ${id}).\nResponse provided: ${Array.isArray(responseData) ? JSON.stringify(responseData) : responseData}`,);
                        } else if (dnsRequestData[0].recordType === 'TXT') {
                            let singleText = typeof (responseData) === 'string';
                            let listOfTexts = Array.isArray(responseData) ? responseData.map(x => typeof (x) === 'string').reduce((acum, cur) => acum && cur, true) : false;

                            if (singleText) dnsResponseBuffer = construct_TXT_Record_Response(dnsRequestData[0], [responseData]);
                            else if (listOfTexts) dnsResponseBuffer = construct_TXT_Record_Response(dnsRequestData[0], responseData);
                            else throw new Error(`DNS Response Error: Response Data is not a valid string or list of strings for (Domain: ${domain}, RecordType: ${recordType}, ID: ${id})`,);
                        } else if (dnsRequestData[0].recordType === 'NS') {
                            let singleSubdomain = typeof (responseData) === 'string';
                            let listOfSubdomains = Array.isArray(responseData) ? responseData.map(x => typeof (x) === 'string').reduce((acum, cur) => acum && cur, true) : false;

                            if (singleSubdomain) dnsResponseBuffer = construct_NS_Record_Response(dnsRequestData[0], [responseData]);
                            else if (listOfSubdomains) dnsResponseBuffer = construct_NS_Record_Response(dnsRequestData[0], responseData);
                            else throw new Error(`DNS Response Error: Response Data is not a valid sub-domain or list of sub-domains for (Domain: ${domain}, RecordType: ${recordType}, ID: ${id})`,);
                        }

                        if (dnsResponseBuffer) {
                            SERVER_SOCKET.send(dnsResponseBuffer, messageInfo.port, messageInfo.address, (err) => {
                                if (err) throw new Error('Error while sending DNS Response');
                            });
                        }
                    }
                } catch (err) {
                    if (CALLBACK_ON_ERROR && typeof (CALLBACK_ON_ERROR) === 'function') {
                        CALLBACK_ON_ERROR(err);
                    }
                }
            });

            SERVER_SOCKET.on('listening', () => {
                if (CALLBACK_ON_START && typeof (CALLBACK_ON_START) === 'function') {
                    CALLBACK_ON_START();
                }
            });

            SERVER_SOCKET.on('error', (err) => {
                if (CALLBACK_ON_ERROR && typeof (CALLBACK_ON_ERROR) === 'function') {
                    CALLBACK_ON_ERROR(err);
                }
            });

            SERVER_SOCKET.bind({
                port: SERVER_PORT,
                address: LOCAL_HOST_ONLY ? '127.0.0.1' : '0.0.0.0'
            });
        } catch (err) {
            if (CALLBACK_ON_ERROR && typeof (CALLBACK_ON_ERROR) === 'function') {
                CALLBACK_ON_ERROR(err);
            }
        }
    }

    stop() {
        try {
            SERVER_SOCKET.close(() => {
                if (CALLBACK_ON_STOP && typeof (CALLBACK_ON_STOP) === 'function') {
                    CALLBACK_ON_STOP();
                }
            });
            SERVER_SOCKET = null;
        } catch (err) {
            if (CALLBACK_ON_ERROR && typeof (CALLBACK_ON_ERROR) === 'function') {
                CALLBACK_ON_ERROR(err);
            }
        }
    }
}

Object.entries(RECORD_ID_TO_TYPE_LOOKUP).forEach(pair => {
    RECORD_TYPE_TO_ID_LOOKUP[pair[1]] = parseInt(pair[0]);
})

const checks1 = [
    [isIPv4('0.0.0.0'), true],
    [isIPv4('127.0.0.1'), true],
    [isIPv4('256.256.256.256'), false],
    [isIPv4('1.1.1.1'), true],
    [isIPv4('1.1.1.1.'), false],
    [isIPv4('1.1.1.1.1'), false],
    [isIPv4('.1.1.1.1'), false],
    [isIPv4('a.a.a.a'), false],
    [isIPv4(''), false],
    [isIPv4({}), false],
    [isIPv4([]), false],
    [isIPv4(0), false],
    [isIPv4(1), false],
    [isIPv4(null), false],
    [isIPv4(undefined), false],
];

checks1.map(x => x[0] === x[1]).forEach((x, index) => {
    if (!x) {
        console.log('**************************************************');
        console.log(`IPv4 Test case Failed at index: ${index}`);
        console.log('**************************************************');
        process.exit(1);
    }
});

const checks2 = [
    [isIPv6('2001:db8:1111:2222:3333::51'), true],
    [isIPv6('2001:db8:1111:2g22:3333::51'), false],
    [isIPv6('2001:db8:1111:2-22:3333::51'), false],
    [isIPv6('2001:db8:1111:2%22:3333::51'), false],
    [isIPv6('2001:0db8:0000:0000:0000:ff00:0042:8329'), true],
    [isIPv6('2001:db8:0:0:0:ff00:42:8329'), true],
    [isIPv6('2001:db8::ff00:42:8329'), true],
    [isIPv6('2001:0db8:0000:0000:0000:ff00:0042:83291'), false],
    [isIPv6('1.1.1.1'), false],
    [isIPv6('1.1.1.1.1'), false],
    [isIPv6(''), false],
    [isIPv6({}), false],
    [isIPv6([]), false],
    [isIPv6(0), false],
    [isIPv6(1), false],
    [isIPv6(null), false],
    [isIPv6(undefined), false],
];

checks2.map(x => x[0] === x[1]).forEach((x, index) => {
    if (!x) {
        console.log('**************************************************');
        console.log(`IPv6 Test case Failed at index: ${index}`);
        console.log('**************************************************');
        process.exit(1);
    }
});

module.exports = DnsServer;