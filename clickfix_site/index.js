const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;

// Serve static files from a 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Basic route
app.get('/clickfix', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'clickfix.html'));
});

app.listen(PORT, () => {
  console.log(`clickfix_site server running on port ${PORT}`);
});
