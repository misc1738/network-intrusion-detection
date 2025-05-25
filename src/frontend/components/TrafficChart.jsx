import React, { useState, useEffect } from 'react';
import { Line } from 'react-chartjs-2';
import { Paper, Typography } from '@mui/material';
import {
    Chart as ChartJS,
    CategoryScale,
    LinearScale,
    PointElement,
    LineElement,
    Title,
    Tooltip,
    Legend
} from 'chart.js';

ChartJS.register(
    CategoryScale,
    LinearScale,
    PointElement,
    LineElement,
    Title,
    Tooltip,
    Legend
);

const TrafficChart = () => {
    const [trafficData, setTrafficData] = useState({
        labels: [],
        datasets: [{
            label: 'Network Traffic (packets/s)',
            data: [],
            borderColor: 'rgb(75, 192, 192)',
            tension: 0.1
        }]
    });

    useEffect(() => {
        const ws = new WebSocket('ws://localhost:3000/ws');

        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            setTrafficData(prevData => ({
                labels: [...prevData.labels, new Date().toLocaleTimeString()].slice(-20),
                datasets: [{
                    ...prevData.datasets[0],
                    data: [...prevData.datasets[0].data, data.packetsPerSecond].slice(-20)
                }]
            }));
        };

        return () => ws.close();
    }, []);

    return (
        <Paper sx={{ p: 2, height: '400px' }}>
            <Typography variant="h6" gutterBottom>
                Real-time Network Traffic
            </Typography>
            <Line data={trafficData} options={{
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }} />
        </Paper>
    );
};

export default TrafficChart;