import React from 'react';
import { Container, Grid, Paper } from '@mui/material';
import TrafficChart from './TrafficChart';

const Dashboard = () => {
    return (
        <Container maxWidth="lg">
            <Grid container spacing={3}>
                <Grid item xs={12}>
                    <TrafficChart />
                </Grid>
                <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2 }}>
                        <h2>Alerts</h2>
                        {/* Alert component will be added here */}
                    </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2 }}>
                        <h2>System Status</h2>
                        {/* Status component will be added here */}
                    </Paper>
                </Grid>
            </Grid>
        </Container>
    );
};

export default Dashboard;