/**
 * Vercel Serverless Function entry point.
 * Directs /api/* requests through the Express API router.
 */

import express from 'express';
import { apiRouter } from '../src/server/apiRouter';

const app = express();
app.use('/api', apiRouter);

export default app;
