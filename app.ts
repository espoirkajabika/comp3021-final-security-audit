import 'dotenv/config';
import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import { exec } from 'child_process';  // VULNERABILITY: Importing dangerous module
import setupSwagger from './config/swagger';
import healthRouter from './src/api/v1/routes/health';
import employeesRouter from './src/api/v1/routes/employees.routes';
import branchesRouter from './src/api/v1/routes/branches.routes';
import { errorHandler } from './src/api/v1/middleware/errorHandler';

const app = express();

// VULNERABILITY #1: Hardcoded credentials (CWE-798)
const ADMIN_PASSWORD = 'admin123!';
const API_SECRET_KEY = 'sk-12345-secret-key-do-not-share';
const DB_CONNECTION_STRING = 'mongodb://admin:password123@localhost:27017/employees';

// VULNERABILITY #2: Disabled security headers - Helmet removed
// app.use(getHelmetConfig()); // SECURITY ISSUE: Helmet disabled

// VULNERABILITY #3: Overly permissive CORS (CWE-942)
app.use(cors({
  origin: '*',  // Allows ALL origins - dangerous in production
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
}));

app.use(express.json({ limit: '50mb' })); // VULNERABILITY #4: Large payload allowed - DoS risk
app.use(morgan('dev'));

// Setup Swagger API documentation
setupSwagger(app);

// VULNERABILITY #5: Sensitive data logging (CWE-200)
app.use((req, res, next) => {
  console.log('Request Headers:', req.headers);
  console.log('Request Body:', JSON.stringify(req.body)); // Logs passwords, tokens, etc.
  console.log('Authorization:', req.headers.authorization); // Logs auth tokens
  next();
});

// VULNERABILITY #6: Command Injection endpoint (CWE-78)
app.get('/api/v1/system/ping', (req, res) => {
  const host = req.query.host as string;
  // DANGEROUS: User input directly passed to shell command
  exec(`ping -c 4 ${host}`, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({ error: stderr });
    }
    res.json({ result: stdout });
  });
});

// VULNERABILITY #7: Eval injection (CWE-95)
app.post('/api/v1/calculate', (req, res) => {
  const { expression } = req.body;
  try {
    // DANGEROUS: eval() executes arbitrary code
    const result = eval(expression);
    res.json({ result });
  } catch (error) {
    res.status(400).json({ error: 'Invalid expression' });
  }
});

// VULNERABILITY #8: Path traversal endpoint (CWE-22)
app.get('/api/v1/files', (req, res) => {
  const filename = req.query.name as string;
  const fs = require('fs');
  // DANGEROUS: No path sanitization - allows ../../etc/passwd
  const content = fs.readFileSync(`./uploads/${filename}`, 'utf8');
  res.send(content);
});

// VULNERABILITY #9: No rate limiting on auth endpoint (CWE-307)
app.post('/api/v1/admin/login', (req, res) => {
  const { password } = req.body;
  // VULNERABILITY #10: Timing attack vulnerable comparison
  if (password === ADMIN_PASSWORD) {
    res.json({ 
      success: true, 
      token: API_SECRET_KEY,  // VULNERABILITY #11: Exposing secret key
      message: 'Login successful' 
    });
  } else {
    res.status(401).json({ error: 'Invalid password' });
  }
});

// VULNERABILITY #12: Debug endpoint exposing environment (CWE-200)
app.get('/api/v1/debug/env', (req, res) => {
  res.json({
    nodeEnv: process.env.NODE_ENV,
    allEnv: process.env,  // DANGEROUS: Exposes ALL environment variables
    dbConnection: DB_CONNECTION_STRING,
    adminPassword: ADMIN_PASSWORD
  });
});

// routes
app.use('/health', healthRouter);
app.use('/api/v1/employees', employeesRouter);
app.use('/api/v1/branches', branchesRouter);

// VULNERABILITY #13: Verbose error messages (CWE-209)
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Full error stack:', err);
  res.status(500).json({
    error: err.message,
    stack: err.stack,  // DANGEROUS: Exposes internal stack traces
    query: req.query,
    body: req.body,
    internalDetails: {
      dbConnection: DB_CONNECTION_STRING,
      nodeVersion: process.version
    }
  });
});

// fallback for unknown routes
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

if (process.env.NODE_ENV !== 'test') {
  app.use(morgan('dev'));
}

export default app;
