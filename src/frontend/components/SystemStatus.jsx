import React, { useState, useEffect } from 'react';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import CircularProgress from '@mui/material/CircularProgress';
import Box from '@mui/material/Box';
import { useTheme } from '@mui/material/styles';

const SystemStatus = () => {
  const theme = useTheme();
  const [backendStatus, setBackendStatus] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Hardcoded packet capture status
  const packetCaptureStatus = 'Active'; 

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        setLoading(true);
        setError(null); // Reset error before new fetch
        const response = await fetch('/api/status');
        if (!response.ok) {
          throw new Error(`HTTP error! Status: ${response.status}`);
        }
        const data = await response.json();
        setBackendStatus(data.status || 'Unknown');
      } catch (e) {
        console.error('Failed to fetch system status:', e);
        setError(e.message);
        setBackendStatus('Error'); // Indicate error in status text as well
      } finally {
        setLoading(false);
      }
    };

    fetchStatus();
  }, []);

  return (
    <Paper elevation={0} sx={{ p: 2, minHeight: '150px', border: 'none', boxShadow: 'none', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
      {loading && (
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
          <CircularProgress />
          <Typography variant="body2" sx={{ mt: 1 }}>Loading status...</Typography>
        </Box>
      )}
      {error && (
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
          <Typography color="error" variant="h6">Failed to load status</Typography>
          <Typography color="error" variant="body2">{error}</Typography>
        </Box>
      )}
      {!loading && !error && (
        <List disablePadding>
          <ListItem sx={{ py: 1 }} divider>
            <ListItemText 
              primary="Backend" 
              secondary={backendStatus}
              primaryTypographyProps={{ fontWeight: 'medium' }}
              secondaryTypographyProps={{ color: backendStatus === 'Error' ? theme.palette.error.main : 'textSecondary' }}
            />
          </ListItem>
          <ListItem sx={{ py: 1 }}>
            <ListItemText 
              primary="Packet Capture" 
              secondary={packetCaptureStatus}
              primaryTypographyProps={{ fontWeight: 'medium' }}
            />
          </ListItem>
        </List>
      )}
    </Paper>
  );
};

export default SystemStatus;
