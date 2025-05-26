import React from 'react';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import { useTheme } from '@mui/material/styles';

// Severity mapping from backend alert types to UI display
const severityMap = {
  'High Traffic': 'Warning',
  'Port Scan Detected': 'Critical',
  'Failed Login': 'Error',
};

const GetSeverityColor = (alertType, theme) => {
  const severity = severityMap[alertType] || 'Info'; // Default to 'Info' if type is unknown
  switch (severity) {
    case 'Critical':
      return theme.palette.error.main;
    case 'Error':
      return theme.palette.warning.dark; // Using dark variant for 'Error' to differentiate from 'Warning'
    case 'Warning':
      return theme.palette.warning.main;
    case 'Info':
      return theme.palette.info.main;
    default:
      return theme.palette.grey[500];
  }
};

const Alerts = ({ alerts }) => {
  const theme = useTheme();

  // Generate a unique key for each alert
  const generateAlertKey = (alert, index) => {
    return `${alert.timestamp}-${alert.sourceIp}-${index}`;
  };

  return (
    <Paper elevation={0} sx={{ p: 2, minHeight: '200px', border: 'none', boxShadow: 'none' }}>
      {(!alerts || alerts.length === 0) ? (
        <Typography variant="body1">No alerts yet.</Typography>
      ) : (
        <List disablePadding>
          {alerts.map((alert, index) => (
            <ListItem 
              key={generateAlertKey(alert, index)} 
              sx={{ 
                borderLeft: `5px solid ${GetSeverityColor(alert.type, theme)}`, 
                mb: 1, 
                bgcolor: theme.palette.background.default, // Subtle background for differentiation
                p: 1.5 // Padding within each list item
              }}
              divider // Adds a subtle line between items
            >
              <ListItemText
                primaryTypographyProps={{ variant: 'subtitle2', fontWeight: 'medium' }}
                primary={`${severityMap[alert.type] || alert.type}: ${alert.sourceIp} (${alert.packetCount} packets)`}
                secondaryTypographyProps={{ variant: 'caption' }}
                secondary={`Timestamp: ${new Date(alert.timestamp).toLocaleString()}`}
              />
            </ListItem>
          ))}
        </List>
      )}
    </Paper>
  );
};

export default Alerts;
