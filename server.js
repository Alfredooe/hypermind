const express = require('express');
const Hyperswarm = require('hyperswarm');
const crypto = require('crypto');
const b4a = require('b4a');

const app = express();
const PORT = process.env.PORT || 3000;

// --- CONFIGURATION ---
const TOPIC_NAME = 'hypermind-lklynet-v1';
const TOPIC = crypto.createHash('sha256').update(TOPIC_NAME).digest();

const MY_ID = crypto.randomUUID();
let mySeq = 0; 

const seenPeers = new Map();

const sseClients = new Set();

seenPeers.set(MY_ID, { seq: mySeq, lastSeen: Date.now() });

function broadcastUpdate() {
    const data = JSON.stringify({
        count: seenPeers.size,
        direct: swarm.connections.size,
        id: MY_ID
    });
    
    for (const client of sseClients) {
        client.write(`data: ${data}\n\n`);
    }
}

const swarm = new Hyperswarm();

swarm.on('connection', (socket) => {

    const hello = JSON.stringify({ type: 'HEARTBEAT', id: MY_ID, seq: mySeq, hops: 0 });
    socket.write(hello);
    broadcastUpdate(); 

    socket.on('data', (data) => {
        try {
            const msgs = data.toString().split('\n').filter(x => x.trim());
            for (const msgStr of msgs) {
                const msg = JSON.parse(msgStr);
                handleMessage(msg, socket);
            }
        } catch (e) {
            // console.error('Invalid message', e);
        }
    });

    socket.on('close', () => {
        if (socket.peerId && seenPeers.has(socket.peerId)) {
            seenPeers.delete(socket.peerId);
        }
        broadcastUpdate();
    });
    
    socket.on('error', () => {});
});

const discovery = swarm.join(TOPIC);
discovery.flushed().then(() => {
    console.log('[P2P] Joined topic:', TOPIC_NAME);
});

function handleMessage(msg, sourceSocket) {
    if (msg.type === 'HEARTBEAT') {
        const { id, seq, hops } = msg;
        
        if (hops === 0) {
            sourceSocket.peerId = id;
        }
        
        const now = Date.now();
        const stored = seenPeers.get(id);
        
        
        let shouldUpdate = false;
        
        if (!stored) {
            // New peer
            shouldUpdate = true;
        } else if (seq > stored.seq) {
            shouldUpdate = true;
        }
        
        if (shouldUpdate) {
            const wasNew = !stored;
            seenPeers.set(id, { seq, lastSeen: now });
            
            if (wasNew) broadcastUpdate();
            
            if (hops < 3) {
                relayMessage({ ...msg, hops: hops + 1 }, sourceSocket);
            }
        }
    } else if (msg.type === 'LEAVE') {
        const { id, hops } = msg;
        if (seenPeers.has(id)) {
            seenPeers.delete(id);
            broadcastUpdate();
            
            if (hops < 3) {
                relayMessage({ ...msg, hops: hops + 1 }, sourceSocket);
            }
        }
    }
}

function relayMessage(msg, sourceSocket) {
    const data = JSON.stringify(msg) + '\n';
    for (const socket of swarm.connections) {
        if (socket !== sourceSocket) {
            socket.write(data);
        }
    }
}

// Periodic Heartbeat
setInterval(() => {
    mySeq++;
    
    seenPeers.set(MY_ID, { seq: mySeq, lastSeen: Date.now() });

    const heartbeat = JSON.stringify({ type: 'HEARTBEAT', id: MY_ID, seq: mySeq, hops: 0 }) + '\n';
    for (const socket of swarm.connections) {
        socket.write(heartbeat);
    }

    const now = Date.now();
    let changed = false;
    for (const [id, data] of seenPeers) {
        if (now - data.lastSeen > 2500) {
            seenPeers.delete(id);
            changed = true;
        }
    }
    
    if (changed) broadcastUpdate();
    
}, 500);

// Graceful Shutdown
function handleShutdown() {
    console.log('[P2P] Shutting down, sending goodbye...');
    const goodbye = JSON.stringify({ type: 'LEAVE', id: MY_ID, hops: 0 }) + '\n';
    for (const socket of swarm.connections) {
        socket.write(goodbye);
    }
    
    setTimeout(() => {
        process.exit(0);
    }, 500);
}

process.on('SIGINT', handleShutdown);
process.on('SIGTERM', handleShutdown);

// --- WEB SERVER ---

app.get('/', (req, res) => {
    const count = seenPeers.size;
    const directPeers = swarm.connections.size;
    
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Hypermind Counter</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body { 
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; 
                    display: flex; 
                    justify-content: center; 
                    align-items: center; 
                    height: 100vh; 
                    background: #111; 
                    color: #eee; 
                    margin: 0; 
                }
                .container { text-align: center; }
                .count { font-size: 8rem; font-weight: bold; color: #4ade80; transition: color 0.2s; }
                .label { font-size: 1.5rem; color: #9ca3af; margin-top: 1rem; }
                .footer { margin-top: 2rem; font-size: 0.9rem; color: #4b5563; }
                .debug { font-size: 0.8rem; color: #333; margin-top: 1rem; }
                a { color: #4b5563; text-decoration: none; border-bottom: 1px dotted #4b5563; }
                .pulse { animation: pulse 0.5s ease-in-out; }
                @keyframes pulse {
                    0% { transform: scale(1); }
                    50% { transform: scale(1.1); color: #fff; }
                    100% { transform: scale(1); }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div id="count" class="count">${count}</div>
                <div class="label">Active Nodes</div>
                <div class="footer">
                    powered by <a href="https://github.com/lklynet/hypermind" target="_blank">hypermind</a>
                </div>
                <div class="debug">
                    ID: ${MY_ID.slice(0, 8)}...<br>
                    Direct Connections: <span id="direct">${directPeers}</span>
                </div>
            </div>
            <script>
                const countEl = document.getElementById('count');
                const directEl = document.getElementById('direct');
                
                // Use Server-Sent Events for realtime updates
                const evtSource = new EventSource("/events");
                
                evtSource.onmessage = (event) => {
                    const data = JSON.parse(event.data);
                    
                    // Only update and animate if changed
                    if (countEl.innerText != data.count) {
                        countEl.innerText = data.count;
                        countEl.classList.remove('pulse');
                        void countEl.offsetWidth; // trigger reflow
                        countEl.classList.add('pulse');
                    }
                    
                    directEl.innerText = data.direct;
                };
                
                evtSource.onerror = (err) => {
                    console.error("EventSource failed:", err);
                };
            </script>
        </body>
        </html>
    `);
});

// SSE Endpoint
app.get('/events', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    sseClients.add(res);

    const data = JSON.stringify({
        count: seenPeers.size,
        direct: swarm.connections.size,
        id: MY_ID
    });
    res.write(`data: ${data}\n\n`);

    req.on('close', () => {
        sseClients.delete(res);
    });
});

app.get('/api/stats', (req, res) => {
    res.json({ 
        count: seenPeers.size,
        direct: swarm.connections.size,
        id: MY_ID
    });
});

app.listen(PORT, () => {
    console.log(`Hypermind Node running on port ${PORT}`);
    console.log(`ID: ${MY_ID}`);
});
