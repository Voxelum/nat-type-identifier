import dgram, { RemoteInfo, Socket } from "dgram";
import crypto from 'crypto'

// Types for a STUN message

const STUN_TYPE_BIND_REQ = 0x0001
const STUN_TYPE_BIND_RESP = 0x0101
const STUN_TYPE_BIND_ERR_RESP = 0x0111

const STUN_ATTR_MAPPED_ADDR = 0x0001
const STUN_ATTR_RESP_ADDR = 0x0002
const STUN_ATTR_CHANGE_REQ = 0x0003
const STUN_ATTR_SRC_ADDR = 0x0004
const STUN_ATTR_CHANGE_ADDR = 0x0005

// NAT Types
export enum NatType {
  BLOCKED = "Blocked",
  OPEN_INTERNET = "Open Internet",
  FULL_CONE = "Full Cone",
  SYMMETRIC_UDP_FIREWALL = "Symmetric UDP Firewall",
  RESTRICTED_NAT = "Restrict NAT",
  RESTRICTED_PORT_NAT = "Restrict Port NAT",
  SYMMETRIC_NAT = "Symmetric NAT",
}

const CHANGE_ADDR_ERR = "Error occurred during Test on Changed IP and Port";
const LOGS_ACTIVE = "LOGS-ACTIVE";

const defaultSourceIp = "0.0.0.0";
const defaultSourcePort = 54320;

const defaultStunHost = "stun.sipgate.net";
const defaultStunPort = 3478;
const defaultSampleCount = 20;
const sampleCountEventListenerMultiplier = 50;

/* 
   #######################
   Generic/Re-Used Methods
   #######################
*/

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

/* 
   #########################
   Main Methods
   #########################
*/

interface StunResponse {
  /**
   * The public ip address that the stun server seen from your packet
   */
  externalIp: string
  /**
   * The public port address that the stun server seen from your packet
   */
  externalPort: number
  sourceIP?: string
  sourcePort?: number
  changedIP?: string
  changedPort?: number
}

function processBindResponseResponse(message: Buffer, length: number) {
  const responseVal: Partial<StunResponse> = {
    externalIp: undefined,
    externalPort: undefined,
    sourceIP: undefined,
    sourcePort: undefined,
    changedIP: undefined,
    changedPort: undefined,
  };

  // This is where the fun begins...

  let lengthRemaining = length;
  let base = 0;

  while (lengthRemaining > 0) {
    // var attrType = bytesToStr(message.slice(base, base + 2));
    const attrType = message.readInt16BE(base);
    const attrLen = message.readUInt16BE(base + 2);
    // var attrLen = hexValToInt(
    //   `${bytesToStr(message.slice(base + 2, base + 4)).replace(/^0+/, "")}`
    // );
    // Fetch port and ipAddr value from buffer
    const port = message.readUInt16BE(base + 6);
    const octA = message.readUInt8(base + 8); // hexValToInt(`${bytesToStr(message.slice(base + 8, base + 9))}`);
    const octB = message.readUInt8(base + 9); // hexValToInt(`${bytesToStr(message.slice(base + 9, base + 10))}`);
    const octC = message.readUInt8(base + 10); // hexValToInt(`${bytesToStr(message.slice(base + 10, base + 11))}`);
    const octD = message.readUInt8(base + 11); // hexValToInt(`${bytesToStr(message.slice(base + 11, base + 12))}`);
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
  return responseVal;
}

async function sendBindRequest(socket: Socket, host: string, port: number, interval: number, sendData: Buffer = Buffer.from([])) {
  let messageReceived = false;
  let bgOp: NodeJS.Timeout | undefined;
  let onMessage: undefined | ((message: Buffer, remote: RemoteInfo) => void);
  // console.log(`socket ${socket.address().address}:${socket.address().port} ${host}:${port} ${sendData.length}`)
  const transactionIds: Buffer[] = [];
  try {
    return await new Promise<StunResponse | undefined>((resolve) => {
      const sendMessage = (retryCount = 0) => {
        // Generate a transaction ID and push it to list
        const transId = crypto.randomBytes(16)
        // const transactionId = genTransactionId();
        transactionIds.push(transId);

        // Generate hex buffer composed of msg, length, transaction ID, and data to send
        const prxData = Buffer.from([/* stun msg type=BindRequestMsg */ 0, 1, /* leave the space for length */ 0, 0]) // convertToHexBuffer(`${BindRequestMsg}${strLen}`);
        prxData.writeUInt16BE(sendData.length, 2)
        // console.log(`send data buf length ${sndData.length} strLen=${strLen} ${dataToSend.length} ${dataToSend}`)
        const finalData = Buffer.concat([prxData, transId, sendData]);

        // console.log(`send`)
        // console.log(finalData)

        socket.send(
          finalData,
          0,
          finalData.length,
          port,
          host,
          (err, nrOfBytesSent) => {
            // if (settings.includes(LOGS_ACTIVE))
            // console.log("UDP message sent to " + host + ":" + port + ' ' + nrOfBytesSent);
            // Attempt to send messages 3 times otherwise resolve as failure
            bgOp = setTimeout(() => {
              if (!messageReceived) {
                if (retryCount >= 3) {
                  resolve(undefined);
                  return;
                }

                sendMessage(retryCount + 1);
              }
            }, interval);
            // Add timeout obj to array to clear,
            //   if main process completes before timeouts expire
          }
        );
      };

      try {
        onMessage = (buf: Buffer, remote: RemoteInfo) => {
          messageReceived = true;
          const msgType = buf.readUInt16BE();
          const msgLen = buf.readUInt16BE(2);
          const msgTrans = buf.slice(4, 20);
          const matchIndex = transactionIds.findIndex((transId) => msgTrans.compare(transId) === 0);

          if (msgType === STUN_TYPE_BIND_RESP && matchIndex !== -1) {
            const response = processBindResponseResponse(buf.slice(20), msgLen);
            if (response.externalIp && response.externalPort) {
              resolve(response as StunResponse);
            } else {
              // malformed response?
              resolve(undefined);
            }
          } else if (msgType === STUN_TYPE_BIND_ERR_RESP) {
            // error
            resolve(undefined)
          } else {
            // ignore other response
            resolve(undefined)
          }
        };

        // Upon receiving message, handle it as STUN response
        socket.once("message", onMessage);
        sendMessage();
      } catch (error) {
        // if (settings.includes(LOGS_ACTIVE))
        // console.log(error);
        resolve(undefined);
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

export interface UnblockedNatInfo {
  type: NatType.FULL_CONE | NatType.OPEN_INTERNET | NatType.RESTRICTED_NAT | NatType.RESTRICTED_PORT_NAT | NatType.SYMMETRIC_NAT | NatType.SYMMETRIC_UDP_FIREWALL
  /**
   * The external ip of your device
   */
  externalIp: string
  /**
   * The external port of your device
   */
  externalPort: number
}

export interface BlockNatInfo {
  type: NatType.BLOCKED
}

export type NatInfo = BlockNatInfo | UnblockedNatInfo

export interface GetNatInfoOptions {
  /**
   * The stun server address.
   */
  stun?: Address
  /**
   * The local ip and port will be used for sending packet
   */
  local?: Address
  /**
   * The interval in millisecond between udp packet sent to server (if server has no response)
   * @default 5000
   */
  retryInterval?: number
}

type Address = string | {
  ip?: string;
  port?: number;
};


/**
 * Get nat info from you stun
 * @param options 
 * @returns The nat info for th 
 */
export function getNatInfoUDP(options: GetNatInfoOptions = {}) {
  const stunAddr = normalizeAddress(options.stun, defaultStunHost, defaultStunPort)
  const localAddr = normalizeAddress(options.local, defaultSourceIp, defaultSourcePort)
  return createSocket(localAddr, 1, (socket) =>
    getNatInfoUDPInternal(socket, stunAddr.ip, stunAddr.port, options.retryInterval ?? 5000)
  )
}

async function getNatInfoUDPInternal(socket: Socket, stunIp: string, stunPort: number, interval: number): Promise<NatInfo> {
  let stunResult = await sendBindRequest(socket, stunIp, stunPort, interval);
  if (!stunResult) {
    return { type: NatType.BLOCKED };
  }

  const srcAddr = socket.address()

  const exIP = stunResult.externalIp;
  const exPort = stunResult.externalPort;
  const changedIP = stunResult.changedIP;
  const changedPort = stunResult.changedPort;

  if (stunResult.externalIp == srcAddr.address) {
    // try to send change request, 6 (0110) means change ip & port
    const changeRequestBuf = Buffer.from([/* type=change */ 0, STUN_ATTR_CHANGE_REQ, /* length=4 */ 0, 4, /* change ip & port */ 0, 0, 0, 6])
    const newStunResult = await sendBindRequest(
      socket,
      stunIp,
      stunPort,
      interval,
      changeRequestBuf
    );

    return {
      type: newStunResult ? NatType.OPEN_INTERNET : NatType.SYMMETRIC_UDP_FIREWALL,
      externalIp: stunResult.externalIp,
      externalPort: stunResult.externalPort,
    }
  }

  // ask server to try different ip & port
  const changeRequestBuf = Buffer.from([/* type=change */ 0, STUN_ATTR_CHANGE_REQ, /* length=4 */ 0, 4, /* change ip & port */ 0, 0, 0, 6])

  if (await sendBindRequest(
    socket,
    stunIp,
    stunPort,
    interval,
    changeRequestBuf
  )) {
    // full cone if stun can access you via **different** ip & port.
    return {
      type: NatType.FULL_CONE,
      externalIp: stunResult.externalIp,
      externalPort: stunResult.externalPort,
    }
  }

  if (!changedIP || !changedPort) {
    throw new Error(CHANGE_ADDR_ERR)
  }

  const secondStunResult = await sendBindRequest(socket, changedIP, changedPort, interval);

  if (!secondStunResult) {
    throw new Error(CHANGE_ADDR_ERR)
  }

  if (exIP == secondStunResult.externalIp &&
    exPort == secondStunResult.externalPort) {
    // cone like since we reuse the port for different dest ip:port

    // only change port
    const changeRequestBuf = Buffer.from([/* type=change */ 0, STUN_ATTR_CHANGE_ADDR, /* length=4 */ 0, 4, /* change port */ 0, 0, 0, 2])
    const thirdStunResult = await sendBindRequest(
      socket,
      changedIP,
      changedPort,
      interval,
      changeRequestBuf
    );
    return {
      type: thirdStunResult ? NatType.RESTRICTED_NAT : NatType.RESTRICTED_PORT_NAT,
      externalIp: stunResult.externalIp,
      externalPort: stunResult.externalPort,
    }
  }

  // if packet for different ip:port use different port, we are symmetric
  return {
    type: NatType.SYMMETRIC_NAT,
    externalIp: stunResult.externalIp,
    externalPort: stunResult.externalPort,
  }
}

/* 
   ##########################
   Socket Setup & Main Method
   ##########################
*/

function normalizeAddress(addr: Address | undefined, defaultIp: string, defaultPort: number) {
  if (typeof addr === 'string') {
    const [ip, port] = addr.split(':')
    if (port) {
      return { ip, port: Number(port) }
    }
    return { ip, port: defaultPort }
  }
  return { ip: addr?.ip ?? defaultIp, port: addr?.port ?? defaultPort }
}


async function createSocket<T>(socketOp: { ip: string; port: number }, sampleCount: number, run: (socket: Socket) => Promise<T>) {
  const socket: Socket = dgram.createSocket({
    type: "udp4",
    reuseAddr: true,
    recvBufferSize: 2048,
  })
  socket.setMaxListeners(sampleCountEventListenerMultiplier * sampleCount);
  socket.bind(socketOp.port, socketOp.ip);
  await new Promise<void>((resolve, reject) => {
    socket.on('listening', () => {
      resolve()
    })
    socket.on('error', (e) => {
      reject(e)
    })
  })
  try {
    return await run(socket)
  } finally {
    socket.close();
  }
}

export interface DetermineNatOptions {
  /**
   * How many time will the client try to send server to determine the nat type
   */
  sampleCount?: number
  /**
   * The address of the stun server
   */
  stun?: Address
  /**
   * The local address for udp socket to bind.
   */
  local?: Address
  /**
   * The interval in millisecond between udp packet sent to server (if server has no response)
   * @default 5000
   */
  retryInterval?: number
}

/**
 * This will try to sample the nat type by sending stun request to the server many times.
 * It will pick the most frequent NatType result as the final return.
 * 
 * By default, it will sample `20` time, and the default stun server is `stun.sipgate.net`.
 * 
 * @param options The sample nat option.
 * @returns 
 */
export async function sampleNatType(options: DetermineNatOptions = {}) {
  const {
    sampleCount = defaultSampleCount,
    stun,
    local,
  } = options;

  return await createSocket(normalizeAddress(local, defaultSourceIp, defaultSourcePort), sampleCount, async (socket) => {
    const { ip, port } = normalizeAddress(stun, defaultStunHost, defaultStunPort)

    const resultsList: NatInfo[] = [];
    // Take N samples and find mode value (to determine most probable NAT type)
    for (let i = 0; i < sampleCount; i++) {
      const result = await getNatInfoUDPInternal(socket, ip, port, options.retryInterval ?? 5000);
      resultsList.push(result);
    }

    // Clear timeout operations on socket.messages
    const determinedNatType = getModeFromArray(resultsList.map(r => r.type));

    return determinedNatType;
  });
  // if (settings.includes(LOGS_ACTIVE)) {
  //   console.log("\nDetermined NAT Type: ", determinedNatType);
  //   console.log(
  //     `A mode value is selected using a ${sampleCount} test samples as failed responses via UDP can cause inaccurate results.`
  //   );
  // }
}
