import React, { useState, useEffect } from 'react';
import { Container, Grid, Paper } from '@mui/material';
import TrafficChart from './TrafficChart';
import Alerts from './Alerts';
import SystemStatus from './SystemStatus';

const MAX_ALERTS = 10; // Define a maximum number of alerts to keep

const Dashboard = () => {
    const [alerts, setAlerts] = useState([]);

    // Callback to add new alerts, ensuring the list doesn't grow indefinitely
    const handleNewAlert = (newAlert) => {
        setAlerts(prevAlerts => {
            const updatedAlerts = [newAlert, ...prevAlerts];
            if (updatedAlerts.length > MAX_ALERTS) {
                return updatedAlerts.slice(0, MAX_ALERTS);
            }
            return updatedAlerts;
        });
    };

    return (
        <Container maxWidth="lg">
            <Grid container spacing={3}>
                <Grid item xs={12}>
                    <TrafficChart onNewAlert={handleNewAlert} />
                </Grid>
                <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2 }}>
                        <Alerts alerts={alerts} />
                    </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2 }}>
                        <SystemStatus />
                    </Paper>
                </Grid>
            </Grid>
        </Container>
    );
};

export default Dashboard;