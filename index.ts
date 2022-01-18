import dgram, { RemoteInfo, Socket } from "dgram";
// import binascii from "binascii";
import crypto from 'crypto'
// import cryptoRandomString from "crypto-random-string";

// Types for a STUN message
const BindRequestMsg = "0001";
const BIND_REQ_MSG = Buffer.from([0, 1])

const msgTypes: Record<string, string> = {
  "0001": "BindRequestMsg",
  "0101": "BindResponseMsg",
  "0111": "BindErrorResponseMsg",
  "0002": "SharedSecretRequestMsg",
  "0102": "SharedSecretResponseMsg",
  "0112": "SharedSecretErrorResponseMsg",
};

const STUN_ATTR_MAPPED_ADDR = 1
const STUN_ATTR_RESP_ADDR = 2
const STUN_ATTR_CHANGE_REQ = 3
const STUN_ATTR_SRC_ADDR = 4
const STUN_ATTR_CHANGE_ADDR = 5

const stunAttributes = {
  MappedAddress: "0001",
  ResponseAddress: "0002",
  ChangeRequest: "0003",
  SourceAddress: "0004",
  ChangedAddress: "0005",
};

// NAT Types
const BLOCKED = "Blocked";
const OPEN_INTERNET = "Open Internet";
const FULL_CONE = "Full Cone";
const SYMMETRIC_UDP_FIREWALL = "Symmetric UDP Firewall";
const RESTRICTED_NAT = "Restric NAT";
const RESTRICTED_PORT_NAT = "Restric Port NAT";
const SYMMETRIC_NAT = "Symmetric NAT";
const ERROR = "Error";

export type NatType =
  typeof BLOCKED |
  typeof OPEN_INTERNET |
  typeof FULL_CONE |
  typeof SYMMETRIC_UDP_FIREWALL |
  typeof RESTRICTED_NAT |
  typeof RESTRICTED_PORT_NAT |
  typeof SYMMETRIC_NAT |
  typeof ERROR

const CHANGE_ADDR_ERR = "Error occurred during Test on Changed IP and Port";
const LOGS_ACTIVE = "LOGS-ACTIVE";

const sourceIp = "0.0.0.0";
const sourcePort = 54320;

const backgroundOps = [];
const transactionIds: Buffer[] = [];

const defaultStunHost = "stun.sipgate.net";
const defaultSampleCount = 20;
const sampleCountEventListenerMultiplier = 50;

/* 
   #######################
   Generic/Re-Used Methods
   #######################
*/

function pad(num: string | number, size: number) {
  num = num.toString();
  while (num.length < size) num = "0" + num;
  return num;
}

function bytesToStr(bytes: Uint8Array) {
  return `${pad(bytes[0].toString(16), 2)}${!!bytes[1] ? pad(bytes[1].toString(16), 2) : ""
    }`;
}

// function bytesValToMsgType(bytes: Uint8Array) {
//   return msgTypes[`${bytesToStr(bytes)}`];
// }

// export function convertToHexBuffer(text: string) {
//   return Buffer.from(binascii.a2b_hex(text).toUpperCase());
// }

// function hexValToInt(hex: string) {
//   return parseInt(Number(`0x${hex}`), 10);
// }

function getModeFromArray(array: NatType[]) {
  var modeMap: Record<string, number> = {};
  var modeElement = array[0],
    maxCount = 1;

  if (array.length == 0) {
    return null;
  }

  for (var i = 0; i < array.length; i++) {
    var elem = array[i];
    if (!modeMap[elem]) {
      modeMap[elem] = 1
    } else {
      modeMap[elem]++
    }
    // modeMap[elem] == null ? (modeMap[elem] = 1) : modeMap[elem]++;
    if (modeMap[elem] > maxCount) {
      modeElement = elem;
      maxCount = modeMap[elem];
    }
  }
  return modeElement;
}

export interface GetIpInfoOptions {
  stunHost: string
  stunPort?: number
}

/* 
   #########################
   Main Methods
   #########################
*/

async function getIpInfo({ stunHost, stunPort = 3478 }: GetIpInfoOptions, index: number): Promise<NatType> {
  var natType = await getNatType(socket, sourceIp, stunHost, stunPort);

  if (!!natType) {
    // If a network error occurred then try running the test again
    if (natType === CHANGE_ADDR_ERR || natType === BLOCKED) {
      return await getIpInfo({ stunHost }, index);
    }
    // if (settings.includes(LOGS_ACTIVE))
    console.log(`Test #${index} - NAT TYPE: ${natType}`);
    return natType as any;
  }
  return ERROR;
};

// export const genTransactionId = () => {
//   // Generates a numeric transaction ID
//   return cryptoRandomString({ length: 32, type: "numeric" });
// };

export interface StunResponse {
  resp: boolean
  /**
   * The public ip address that the stun server seen from your packet
   */
  externalIp?: string
  /**
   * The public port address that the stun server seen from your packet
   */
  externalPort?: number
  sourceIP?: string
  sourcePort?: number
  changedIP?: string
  changedPort?: number
}

const parseStunTestResponse = (address: string, port: number, message: Buffer) => {
  const responseVal: StunResponse = {
    resp: false,
    externalIp: undefined,
    externalPort: undefined,
    sourceIP: undefined,
    sourcePort: undefined,
    changedIP: undefined,
    changedPort: undefined,
  };

  const msgType = message.slice(0, 2);

  // Check the response message type
  // const bindRespMsg = bytesValToMsgType(msgType) == "BindResponseMsg";
  const bindRespMsg = msgType.compare(Buffer.from([1, 1])) === 0;

  // Check that the transaction IDs match, 0xc2 value is removed as it is
  // an annoying UTF-8 encode byte that messes up the entire comparison
  const transIdMatch = transactionIds.find((transId) =>
    transId.compare(message.slice(4, 20)) === 0
  );
  for (const id of transactionIds) {
    console.log(id)
  }

  if (bindRespMsg && !!transIdMatch) {
    transactionIds.slice(transactionIds.length);
    // This is where the fun begins...
    responseVal.resp = true;
    const msgLen = message.readUInt16BE(2);

    let lengthRemaining = msgLen;
    let base = 20;

    while (lengthRemaining > 0) {
      // var attrType = bytesToStr(message.slice(base, base + 2));
      const attrType = message.slice(base, base + 2).readUInt16BE();
      const attrLen = message.slice(base + 2, base + 4).readUInt16BE()
      // var attrLen = hexValToInt(
      //   `${bytesToStr(message.slice(base + 2, base + 4)).replace(/^0+/, "")}`
      // );

      // Fetch port and ipAddr value from buffer
      const port = message.readUInt16BE(base + 6);
      const octA = message.readUInt8(base + 8) // hexValToInt(`${bytesToStr(message.slice(base + 8, base + 9))}`);
      const octB = message.readUInt8(base + 9) // hexValToInt(`${bytesToStr(message.slice(base + 9, base + 10))}`);
      const octC = message.readUInt8(base + 10) // hexValToInt(`${bytesToStr(message.slice(base + 10, base + 11))}`);
      const octD = message.readUInt8(base + 11) // hexValToInt(`${bytesToStr(message.slice(base + 11, base + 12))}`);
      const ipAddr = [octA, octB, octC, octD].join(".");

      switch (attrType) {
        case STUN_ATTR_MAPPED_ADDR:
          responseVal.externalIp = ipAddr;
          responseVal.externalPort = port;
        case STUN_ATTR_SRC_ADDR:
          responseVal.sourceIP = ipAddr;
          responseVal.sourcePort = port;
        case STUN_ATTR_CHANGE_ADDR:
          responseVal.changedIP = ipAddr;
          responseVal.changedPort = port;
        default:
          break;
      }

      base = base + 4 + attrLen;
      lengthRemaining = lengthRemaining - (4 + attrLen);
    }
  }

  console.log(responseVal)

  return responseVal;
};

async function stunTest(socket: Socket, host: string, port: number, sendData: Buffer = Buffer.from([])) {
  var messageReceived = false;
  var bgOp: NodeJS.Timeout | undefined;
  var onMessage: undefined | ((message: Buffer, remote: RemoteInfo) => void);
  try {
    return await new Promise<StunResponse>((resolve) => {
      const sendMessage = (counter_1 = 0, recursiveSendData?: Buffer) => {
        const dataToSend = recursiveSendData ? recursiveSendData : sendData;
        const strLen = pad(dataToSend.length, 4);
        // Generate a transaction ID and push it to list
        const transId = crypto.randomBytes(16)
        // const transactionId = genTransactionId();
        console.log(`transaction id ${transId}`)
        console.log(transId)
        transactionIds.push(transId);

        // Generate hex buffer composed of msg, length, transaction ID, and data to send
        const prxData = Buffer.from([/* stun msg type=BindRequestMsg */ 0, 1, 0, 0]) // convertToHexBuffer(`${BindRequestMsg}${strLen}`);
        prxData.writeUInt16BE(dataToSend.length, 2)
        // const transId = convertToHexBuffer(transactionId).slice(0, 16);
        // const sndData = convertToHexBuffer(dataToSend);
        // console.log(`send data buf length ${sndData.length} strLen=${strLen} ${dataToSend.length} ${dataToSend}`)
        const finalData = Buffer.concat([prxData, transId, dataToSend]);

        socket.send(
          finalData,
          0,
          finalData.length,
          port,
          host,
          (err, nrOfBytesSent) => {
            // if (settings.includes(LOGS_ACTIVE))
            console.log("UDP message sent to " + host + ":" + port + ' ' + nrOfBytesSent);
            // Attempt to send messages 3 times otherwise resolve as failure
            bgOp = setTimeout(() => {
              if (!messageReceived) {
                if (counter_1 >= 3) {
                  resolve({ resp: false });
                  return;
                }

                sendMessage(counter_1 + 1, dataToSend);
              }
            }, 5000);
            // Add timeout obj to array to clear,
            //   if main process completes before timeouts expire
            backgroundOps.push(bgOp);
          }
        );
      };

      try {
        onMessage = (message_1: Buffer, remote_1: RemoteInfo) => {
          messageReceived = true;
          const response = parseStunTestResponse(
            remote_1.address,
            remote_1.port,
            message_1);

          resolve(response);
        };

        // Upon receiving message, handle it as STUN response
        socket.once("message", onMessage);
        sendMessage();
      } catch (error) {
        // if (settings.includes(LOGS_ACTIVE))
        console.log(error);
        resolve({ resp: false });
      }
    });
  } finally {
    // remove listener if one was added
    if (onMessage) {
      socket.off("message", onMessage);
    }
    // remove any pending tasks
    if (bgOp) {
      clearTimeout(bgOp);
    }
  }
}

async function getNatType(socket: Socket, sourceIp: string, stunHost: string, stunPort: number) {
  let type: NatType = "Error";
  let stunResult: StunResponse | undefined;

  stunResult = await stunTest(socket, stunHost, stunPort);
  if (!stunResult.resp || !stunResult) {
    return BLOCKED;
  }

  const exIP = stunResult.externalIp;
  const exPort = stunResult.externalPort;
  const changedIP = stunResult.changedIP;
  const changedPort = stunResult.changedPort;

  // const msgAttrLen = "0004";

  if (stunResult.externalIp == sourceIp) {
    // try to send change request, 6 (0110) means change ip & port
    // const changeRequest = `${stunAttributes.ChangeRequest}${msgAttrLen}00000006`;
    const changeRequestBuf = Buffer.from([/* type=change */ 0, STUN_ATTR_CHANGE_REQ, /* length=4 */ 0, 4, /* change ip & port */ 0, 0, 0, 6])
    const newStunResult = await stunTest(
      socket,
      stunHost,
      stunPort,
      changeRequestBuf
    );

    if (newStunResult.resp) {
      type = OPEN_INTERNET;
    } else {
      type = SYMMETRIC_UDP_FIREWALL;
    }
  } else {
    // var changeRequest = `${stunAttributes.ChangeRequest}${msgAttrLen}00000006`;
    const changeRequestBuf = Buffer.from([/* type=change */ 0, STUN_ATTR_CHANGE_REQ, /* length=4 */ 0, 4, /* change ip & port */ 0, 0, 0, 6])
    const secondStunResult = await stunTest(
      socket,
      stunHost,
      stunPort,
      changeRequestBuf
    );

    if (secondStunResult.resp) {
      type = FULL_CONE;
    } else {
      const secondStunResult = await stunTest(socket, changedIP!, changedPort!);

      if (!secondStunResult.resp) {
        type = CHANGE_ADDR_ERR;
      } else {
        if (exIP == secondStunResult.externalIp &&
          exPort == secondStunResult.externalPort) {
          // var changePortRequest = `${stunAttributes.ChangeRequest}${msgAttrLen}00000002`;
          // only change port
          const changeRequestBuf = Buffer.from([/* type=change */ 0, STUN_ATTR_CHANGE_ADDR, /* length=4 */ 0, 4, /* change port */ 0, 0, 0, 2])
          var thirdStunResult = await stunTest(
            socket,
            changedIP!,
            stunPort,
            changeRequestBuf
          );
          if (thirdStunResult.resp) {
            type = RESTRICTED_NAT;
          } else {
            type = RESTRICTED_PORT_NAT;
          }
        } else {
          type = SYMMETRIC_NAT;
        }
      }
    }
  }

  return type;
}

/* 
   ##########################
   Socket Setup & Main Method
   ##########################
*/

const socket = dgram.createSocket({
  type: "udp4",
  reuseAddr: true,
  recvBufferSize: 2048,
});

const getDeterminedNatType = async (sampleCount: number, stunHost: string) => {
  socket.setMaxListeners(sampleCountEventListenerMultiplier * sampleCount);
  socket.bind(sourcePort, sourceIp);

  const resultsList = [];
  // Take 20 samples and find mode value (to determine most probable NAT type)
  for (var i = 0; i < sampleCount; i++) {
    const result = await getIpInfo({ stunHost }, i + 1);
    resultsList.push(result);
  }

  socket.close();
  // Clear timeout operations on socket.messages
  backgroundOps.map((op) => clearTimeout(op));
  const determinedNatType = getModeFromArray(resultsList);
  if (settings.includes(LOGS_ACTIVE)) {
    console.log("\nDetermined NAT Type: ", determinedNatType);
    console.log(
      `A mode value is selected using a ${sampleCount} test samples as failed responses via UDP can cause inaccurate results.`
    );
  }
  return determinedNatType;
};

export default async ({ sampleCount = 20, stunHost = defaultStunHost }) => {
  return await getDeterminedNatType(defaultSampleCount, defaultStunHost);
}
