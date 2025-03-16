const express = require('express');
const path = require('path');
const { spawn } = require('child_process');

const app = express();
app.use(express.json()); // parse JSON bodies
app.use(express.static(path.join(__dirname, 'public')));

app.post('/run-python', (req, res) => {
  // The front end can post data to this route
  const inputData = JSON.stringify(req.body);
  const pyProcess = spawn('python3', [
    path.join(__dirname, req.body.script),
    // Script needs be specified from the template in the flow.js
    inputData
  ]);

  let outputData = '';
  pyProcess.stdout.on('data', (chunk) => {
    outputData += chunk;
  });

  pyProcess.stderr.on('data', (err) => {
    console.error('Python error:', err.toString());
  });

  pyProcess.on('close', (code) => {
    // parse the JSON that Python printed
    try {
      const parsed = JSON.parse(outputData);
      res.json(parsed);
    } catch (e) {
      res.status(500).send('Error parsing Python output');
    }
  });
});

app.listen(3000, () => {
  console.log('Server listening on http://localhost:3000');
});