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

// Track packets per second and source IP counts
let packetCount = 0;
let sourceIpCounts = {};
const alertThreshold = 100; // Packets per second from a single IP to trigger an alert

setInterval(() => {
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({ type: 'metrics', data: { packetsPerSecond: packetCount } }));
        }
    });
    packetCount = 0;
    sourceIpCounts = {}; // Reset IP counts every second
}, 1000);

// Start packet capture
try {
    const pcapSession = pcap.createSession('', 'ip proto \\tcp or \\udp'); // Listen for TCP or UDP over IP
    
    pcapSession.on('packet', (raw_packet) => {
        packetCount++;
        try {
            const packet = pcap.decode.packet(raw_packet);

            // Check for IPv4 packet (EtherType 0x0800)
            if (packet.payload && packet.payload.ethertype === 2048) {
                const ipv4Packet = packet.payload.payload;
                if (ipv4Packet && ipv4Packet.saddr) {
                    const sourceIp = ipv4Packet.saddr.addr.join('.');
                    
                    sourceIpCounts[sourceIp] = (sourceIpCounts[sourceIp] || 0) + 1;

                    if (sourceIpCounts[sourceIp] > alertThreshold) {
                        const alert = {
                            type: 'High Traffic',
                            sourceIp: sourceIp,
                            packetCount: sourceIpCounts[sourceIp],
                            timestamp: new Date().toISOString()
                        };
                        
                        // Send alert to all connected clients
                        wss.clients.forEach(client => {
                            if (client.readyState === WebSocket.OPEN) {
                                client.send(JSON.stringify({ type: 'alert', data: alert }));
                            }
                        });
                        // Optional: To avoid flooding with alerts for the same IP in the same second,
                        // you might want to mark this IP as alerted for this interval or reset its count.
                        // For simplicity, this example will allow multiple alerts if traffic continues.
                    }
                }
            }
        } catch (decodeError) {
            console.error('Error decoding packet:', decodeError);
        }
    });

    console.log('Packet capture started, listening for TCP/UDP packets.');
} catch (error) {
    console.error('Failed to start packet capture:', error);
}