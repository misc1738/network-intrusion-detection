const express = require('express');
const app = express();
const WebSocket = require('ws');
const pcap = require('pcap');

const PORT = process.env.PORT || 3000;

app.use(express.json());

// Basic route
app.get('/api/status', (req, res) => {
    res.json({ status: 'running' });
});

// Create WebSocket server
const server = app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

const wss = new WebSocket.Server({ server });

// Track packets per second
let packetCount = 0;
setInterval(() => {
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({ packetsPerSecond: packetCount }));
        }
    });
    packetCount = 0;
}, 1000);

// Start packet capture
try {
    const pcapSession = pcap.createSession('', 'ip proto \\tcp or \\udp');
    
    pcapSession.on('packet', () => {
        packetCount++;
    });

    console.log('Packet capture started');
} catch (error) {
    console.error('Failed to start packet capture:', error);
}